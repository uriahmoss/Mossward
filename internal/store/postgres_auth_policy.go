package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"mossward/internal/model"
)

func (s *PostgreSQLStore) AuthenticationPolicy() (model.AuthenticationPolicy, error) {
	var encoded string
	err := s.db.QueryRow(`SELECT value FROM app_metadata WHERE key=$1`, authenticationPolicyKey).Scan(&encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return defaultAuthenticationPolicy(), nil
	}
	if err != nil {
		return model.AuthenticationPolicy{}, fmt.Errorf("load PostgreSQL authentication policy: %w", err)
	}
	var policy model.AuthenticationPolicy
	if err := json.Unmarshal([]byte(encoded), &policy); err != nil {
		return model.AuthenticationPolicy{}, fmt.Errorf("decode PostgreSQL authentication policy: %w", err)
	}
	return policy, nil
}

func (s *PostgreSQLStore) SaveAuthenticationPolicy(policy model.AuthenticationPolicy, now time.Time, event model.AuditEvent) error {
	encoded, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("encode PostgreSQL authentication policy: %w", err)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL authentication policy update: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO app_metadata(key,value) VALUES($1,$2)
		ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value`, authenticationPolicyKey, string(encoded)); err != nil {
		return fmt.Errorf("store PostgreSQL authentication policy: %w", err)
	}
	cutoff := now.AddDate(0, 0, -policy.AuditRetentionDays).UTC()
	if _, err := tx.Exec(`SELECT apply_audit_retention($1)`, cutoff); err != nil {
		return fmt.Errorf("apply PostgreSQL audit retention policy: %w", err)
	}
	if err := insertPostgreSQLAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgreSQLStore) ListAuditEvents(query model.AuditQuery) ([]model.AuditEvent, error) {
	clauses := []string{"1=1"}
	arguments := []any{}
	if query.Text != "" {
		clauses = append(clauses, `(action ILIKE ? OR target_id ILIKE ? OR details::text ILIKE ?)`)
		term := "%" + query.Text + "%"
		arguments = append(arguments, term, term, term)
	}
	if query.Severity != "" {
		clauses = append(clauses, `severity=?`)
		arguments = append(arguments, query.Severity)
	}
	arguments = append(arguments, query.Limit)
	statement := `SELECT id,occurred_at,COALESCE(actor_id,''),action,severity,target_type,target_id,source_ip,details
		FROM audit_events WHERE ` + strings.Join(clauses, " AND ") + ` ORDER BY occurred_at DESC LIMIT ?`
	rows, err := s.db.Query(bindQuery(dialectPostgreSQL, statement), arguments...)
	if err != nil {
		return nil, fmt.Errorf("list PostgreSQL audit events: %w", err)
	}
	defer rows.Close()
	items := []model.AuditEvent{}
	for rows.Next() {
		var event model.AuditEvent
		var details []byte
		if err := rows.Scan(&event.ID, &event.OccurredAt, &event.ActorID, &event.Action, &event.Severity,
			&event.TargetType, &event.TargetID, &event.SourceIP, &details); err != nil {
			return nil, fmt.Errorf("scan PostgreSQL audit event: %w", err)
		}
		event.OccurredAt = event.OccurredAt.UTC()
		event.Details = string(details)
		items = append(items, event)
	}
	return items, rows.Err()
}
