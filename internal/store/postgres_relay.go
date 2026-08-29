package store

import (
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"time"

	"mossward/internal/model"
)

func (s *PostgreSQLStore) PromoteEndpointRelay(authorization model.EndpointRelayAuthorization, event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL endpoint relay promotion: %w", err)
	}
	defer tx.Rollback()
	status, err := lockPostgreSQLEndpointStatus(tx, authorization.EndpointID)
	if err != nil {
		return err
	}
	if status != model.EndpointActive {
		return ErrEndpointRelayUnavailable
	}
	var activeID string
	err = tx.QueryRow(`SELECT id FROM endpoint_relay_authorizations WHERE endpoint_id=$1 AND status='active'`,
		authorization.EndpointID).Scan(&activeID)
	if err == nil {
		return ErrEndpointRelayAlreadyActive
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("check PostgreSQL endpoint relay authorization: %w", err)
	}
	_, err = tx.Exec(`INSERT INTO endpoint_relay_authorizations
		(id,endpoint_id,status,promotion_reason,promoted_by,promoted_at) VALUES($1,$2,'active',$3,$4,$5)`,
		authorization.ID, authorization.EndpointID, authorization.PromotionReason, authorization.PromotedBy,
		authorization.PromotedAt)
	if err != nil {
		return fmt.Errorf("promote PostgreSQL endpoint relay: %w", err)
	}
	if err := insertPostgreSQLAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgreSQLStore) RevokeEndpointRelay(endpointID, reason, actorID string, now time.Time, event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL endpoint relay revocation: %w", err)
	}
	defer tx.Rollback()
	if _, err := lockPostgreSQLEndpointStatus(tx, endpointID); err != nil {
		return err
	}
	result, err := tx.Exec(`UPDATE endpoint_relay_authorizations SET status='revoked',revocation_reason=$1,
		revoked_by=$2,revoked_at=$3 WHERE endpoint_id=$4 AND status='active'`, reason, actorID, now, endpointID)
	if err != nil {
		return fmt.Errorf("revoke PostgreSQL endpoint relay: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return ErrNotFound
	}
	downstreamResult, err := tx.Exec(`UPDATE relay_downstream_authorizations SET status='revoked',
		revocation_reason='relay authorization revoked',revoked_by=$1,revoked_at=$2
		WHERE relay_endpoint_id=$3 AND status='active'`, actorID, now, endpointID)
	if err != nil {
		return fmt.Errorf("revoke PostgreSQL relay downstream authorizations: %w", err)
	}
	downstreamCount, err := downstreamResult.RowsAffected()
	if err != nil {
		return fmt.Errorf("count PostgreSQL relay downstream revocations: %w", err)
	}
	if downstreamCount > 0 {
		downstreamEvent := event
		downstreamEvent.Action = "endpoint.relay_downstreams.revoked_with_relay"
		downstreamEvent.Details = fmt.Sprintf(`{"count":%d}`, downstreamCount)
		if err := insertPostgreSQLAuditEvent(tx, downstreamEvent); err != nil {
			return err
		}
	}
	if err := insertPostgreSQLAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgreSQLStore) ListEndpointRelayAuthorizations() ([]model.EndpointRelayAuthorization, error) {
	rows, err := s.db.Query(`SELECT id,endpoint_id,status,promotion_reason,promoted_by,promoted_at,
		revocation_reason,revoked_by,revoked_at FROM endpoint_relay_authorizations ORDER BY promoted_at DESC,id`)
	if err != nil {
		return nil, fmt.Errorf("list PostgreSQL endpoint relay authorizations: %w", err)
	}
	defer rows.Close()
	items := []model.EndpointRelayAuthorization{}
	for rows.Next() {
		var item model.EndpointRelayAuthorization
		var revokedAt sql.NullTime
		if err := rows.Scan(&item.ID, &item.EndpointID, &item.Status, &item.PromotionReason, &item.PromotedBy,
			&item.PromotedAt, &item.RevocationReason, &item.RevokedBy, &revokedAt); err != nil {
			return nil, fmt.Errorf("read PostgreSQL endpoint relay authorization: %w", err)
		}
		item.RevokedAt = nullablePostgreSQLTime(revokedAt)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PostgreSQLStore) AuthorizeRelayDownstream(authorization model.RelayDownstreamAuthorization, event model.AuditEvent) error {
	if authorization.RelayEndpointID == authorization.DownstreamEndpointID {
		return ErrRelayDownstreamSelfAssignment
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL relay downstream authorization: %w", err)
	}
	defer tx.Rollback()
	statuses, err := lockPostgreSQLEndpointStatuses(tx, authorization.RelayEndpointID, authorization.DownstreamEndpointID)
	if err != nil {
		return err
	}
	if _, found := statuses[authorization.RelayEndpointID]; !found {
		return ErrEndpointRelayUnavailable
	}
	if _, found := statuses[authorization.DownstreamEndpointID]; !found {
		return ErrNotFound
	}
	if statuses[authorization.RelayEndpointID] != model.EndpointActive {
		return ErrEndpointRelayUnavailable
	}
	if statuses[authorization.DownstreamEndpointID] != model.EndpointActive {
		return ErrRelayDownstreamUnavailable
	}
	var relayActive int
	err = tx.QueryRow(`SELECT 1 FROM endpoint_relay_authorizations
		WHERE endpoint_id=$1 AND status='active'`, authorization.RelayEndpointID).Scan(&relayActive)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrEndpointRelayUnavailable
	}
	if err != nil {
		return fmt.Errorf("check PostgreSQL active relay authorization: %w", err)
	}
	var existingID string
	err = tx.QueryRow(`SELECT id FROM relay_downstream_authorizations
		WHERE downstream_endpoint_id=$1 AND status='active'`, authorization.DownstreamEndpointID).Scan(&existingID)
	if err == nil {
		return ErrRelayDownstreamAlreadyActive
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("check PostgreSQL relay downstream authorization: %w", err)
	}
	_, err = tx.Exec(`INSERT INTO relay_downstream_authorizations
		(id,relay_endpoint_id,downstream_endpoint_id,status,authorization_reason,authorized_by,authorized_at)
		VALUES($1,$2,$3,'active',$4,$5,$6)`, authorization.ID, authorization.RelayEndpointID,
		authorization.DownstreamEndpointID, authorization.AuthorizationReason, authorization.AuthorizedBy,
		authorization.AuthorizedAt)
	if err != nil {
		return fmt.Errorf("authorize PostgreSQL relay downstream: %w", err)
	}
	if err := insertPostgreSQLAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgreSQLStore) RevokeRelayDownstream(
	relayEndpointID, downstreamEndpointID, reason, actorID string,
	now time.Time,
	event model.AuditEvent,
) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL relay downstream revocation: %w", err)
	}
	defer tx.Rollback()
	if _, err := lockPostgreSQLEndpointStatuses(tx, relayEndpointID, downstreamEndpointID); err != nil {
		return err
	}
	result, err := tx.Exec(`UPDATE relay_downstream_authorizations SET status='revoked',revocation_reason=$1,
		revoked_by=$2,revoked_at=$3 WHERE relay_endpoint_id=$4 AND downstream_endpoint_id=$5 AND status='active'`,
		reason, actorID, now, relayEndpointID, downstreamEndpointID)
	if err != nil {
		return fmt.Errorf("revoke PostgreSQL relay downstream: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return ErrNotFound
	}
	if err := insertPostgreSQLAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgreSQLStore) ListRelayDownstreamAuthorizations() ([]model.RelayDownstreamAuthorization, error) {
	rows, err := s.db.Query(`SELECT id,relay_endpoint_id,downstream_endpoint_id,status,authorization_reason,
		authorized_by,authorized_at,revocation_reason,revoked_by,revoked_at
		FROM relay_downstream_authorizations ORDER BY authorized_at DESC,id`)
	if err != nil {
		return nil, fmt.Errorf("list PostgreSQL relay downstream authorizations: %w", err)
	}
	defer rows.Close()
	items := []model.RelayDownstreamAuthorization{}
	for rows.Next() {
		var item model.RelayDownstreamAuthorization
		var revokedAt sql.NullTime
		if err := rows.Scan(&item.ID, &item.RelayEndpointID, &item.DownstreamEndpointID, &item.Status,
			&item.AuthorizationReason, &item.AuthorizedBy, &item.AuthorizedAt, &item.RevocationReason,
			&item.RevokedBy, &revokedAt); err != nil {
			return nil, fmt.Errorf("read PostgreSQL relay downstream authorization: %w", err)
		}
		item.RevokedAt = nullablePostgreSQLTime(revokedAt)
		items = append(items, item)
	}
	return items, rows.Err()
}

func lockPostgreSQLEndpointStatus(tx *sql.Tx, endpointID string) (model.EndpointStatus, error) {
	var status model.EndpointStatus
	err := tx.QueryRow(`SELECT status FROM endpoints WHERE id=$1 FOR UPDATE`, endpointID).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return status, ErrNotFound
	}
	if err != nil {
		return status, fmt.Errorf("lock PostgreSQL endpoint status: %w", err)
	}
	return status, nil
}

func lockPostgreSQLEndpointStatuses(tx *sql.Tx, endpointIDs ...string) (map[string]model.EndpointStatus, error) {
	sort.Strings(endpointIDs)
	statuses := make(map[string]model.EndpointStatus, len(endpointIDs))
	for _, endpointID := range endpointIDs {
		status, err := lockPostgreSQLEndpointStatus(tx, endpointID)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		statuses[endpointID] = status
	}
	return statuses, nil
}
