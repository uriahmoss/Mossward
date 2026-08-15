package store

import (
	"database/sql"
	"time"

	"mossward/internal/model"
)

func (s *SQLiteStore) PromoteEndpointRelay(authorization model.EndpointRelayAuthorization, event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var status model.EndpointStatus
	if err := tx.QueryRow(`SELECT status FROM endpoints WHERE id=?`, authorization.EndpointID).Scan(&status); err == sql.ErrNoRows {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	if status != model.EndpointActive {
		return ErrEndpointRelayUnavailable
	}
	var activeID string
	if err := tx.QueryRow(`SELECT id FROM endpoint_relay_authorizations WHERE endpoint_id=? AND status='active'`, authorization.EndpointID).Scan(&activeID); err == nil {
		return ErrEndpointRelayAlreadyActive
	} else if err != sql.ErrNoRows {
		return err
	}
	_, err = tx.Exec(`INSERT INTO endpoint_relay_authorizations(id,endpoint_id,status,promotion_reason,promoted_by,promoted_at) VALUES(?,?, 'active',?,?,?)`,
		authorization.ID, authorization.EndpointID, authorization.PromotionReason, authorization.PromotedBy, formatTime(authorization.PromotedAt))
	if err != nil {
		return err
	}
	if err := insertAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLiteStore) RevokeEndpointRelay(endpointID, reason, actorID string, now time.Time, event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.Exec(`UPDATE endpoint_relay_authorizations SET status='revoked',revocation_reason=?,revoked_by=?,revoked_at=? WHERE endpoint_id=? AND status='active'`,
		reason, actorID, formatTime(now), endpointID)
	if err != nil {
		return err
	}
	changed, _ := result.RowsAffected()
	if changed != 1 {
		return ErrNotFound
	}
	if err := insertAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLiteStore) ListEndpointRelayAuthorizations() ([]model.EndpointRelayAuthorization, error) {
	rows, err := s.db.Query(`SELECT id,endpoint_id,status,promotion_reason,promoted_by,promoted_at,revocation_reason,revoked_by,revoked_at FROM endpoint_relay_authorizations ORDER BY promoted_at DESC,id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	authorizations := []model.EndpointRelayAuthorization{}
	for rows.Next() {
		var authorization model.EndpointRelayAuthorization
		var promotedAt string
		var revokedAt sql.NullString
		if err := rows.Scan(&authorization.ID, &authorization.EndpointID, &authorization.Status, &authorization.PromotionReason, &authorization.PromotedBy, &promotedAt,
			&authorization.RevocationReason, &authorization.RevokedBy, &revokedAt); err != nil {
			return nil, err
		}
		authorization.PromotedAt, _ = parseTime(promotedAt)
		if revokedAt.Valid {
			value, _ := parseTime(revokedAt.String)
			authorization.RevokedAt = &value
		}
		authorizations = append(authorizations, authorization)
	}
	return authorizations, rows.Err()
}
