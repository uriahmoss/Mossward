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

const authenticationPolicyKey = "identity.authentication_policy"

func defaultAuthenticationPolicy() model.AuthenticationPolicy {
	return model.AuthenticationPolicy{SessionLifetimeMinutes: 720, AuditRetentionDays: 365,
		MFARequired: map[model.UserRole]bool{model.RoleAdministrator: true, model.RoleAnalyst: true, model.RoleViewer: true}}
}

func (s *SQLiteStore) AuthenticationPolicy() (model.AuthenticationPolicy, error) {
	var encoded string
	err := s.db.QueryRow(`SELECT value FROM app_metadata WHERE key=?`, authenticationPolicyKey).Scan(&encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return defaultAuthenticationPolicy(), nil
	}
	if err != nil {
		return model.AuthenticationPolicy{}, fmt.Errorf("load authentication policy: %w", err)
	}
	var policy model.AuthenticationPolicy
	if err := json.Unmarshal([]byte(encoded), &policy); err != nil {
		return model.AuthenticationPolicy{}, fmt.Errorf("decode authentication policy: %w", err)
	}
	return policy, nil
}

func (s *SQLiteStore) SaveAuthenticationPolicy(policy model.AuthenticationPolicy, now time.Time, event model.AuditEvent) error {
	encoded, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("encode authentication policy: %w", err)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin authentication policy update: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO app_metadata(key, value) VALUES(?, ?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, authenticationPolicyKey, encoded); err != nil {
		return fmt.Errorf("store authentication policy: %w", err)
	}
	cutoff := now.AddDate(0, 0, -policy.AuditRetentionDays)
	if _, err := tx.Exec(`DELETE FROM audit_events WHERE occurred_at<?`, formatTime(cutoff)); err != nil {
		return fmt.Errorf("apply audit retention policy: %w", err)
	}
	if err := insertAuditEvent(tx, event); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit authentication policy update: %w", err)
	}
	return nil
}

func (s *SQLiteStore) ListAuditEvents(query model.AuditQuery) ([]model.AuditEvent, error) {
	clauses := []string{"1=1"}
	args := []any{}
	if query.Text != "" {
		clauses = append(clauses, `(action LIKE ? OR target_id LIKE ? OR details LIKE ?)`)
		term := "%" + query.Text + "%"
		args = append(args, term, term, term)
	}
	if query.Severity != "" {
		clauses = append(clauses, `severity=?`)
		args = append(args, query.Severity)
	}
	args = append(args, query.Limit)
	rows, err := s.db.Query(`SELECT id, occurred_at, COALESCE(actor_id,''), action, severity, target_type,
		target_id, source_ip, details FROM audit_events WHERE `+strings.Join(clauses, " AND ")+` ORDER BY occurred_at DESC LIMIT ?`, args...)
	if err != nil {
		return nil, fmt.Errorf("list audit events: %w", err)
	}
	defer rows.Close()
	items := []model.AuditEvent{}
	for rows.Next() {
		var event model.AuditEvent
		var occurredAt string
		if err := rows.Scan(&event.ID, &occurredAt, &event.ActorID, &event.Action, &event.Severity,
			&event.TargetType, &event.TargetID, &event.SourceIP, &event.Details); err != nil {
			return nil, fmt.Errorf("scan audit event: %w", err)
		}
		if event.OccurredAt, err = parseTime(occurredAt); err != nil {
			return nil, err
		}
		items = append(items, event)
	}
	return items, rows.Err()
}
