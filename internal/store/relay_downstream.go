package store

import (
	"database/sql"
	"time"

	"mossward/internal/model"
)

func (s *SQLiteStore) AuthorizeRelayDownstream(authorization model.RelayDownstreamAuthorization, event model.AuditEvent) error {
	if authorization.RelayEndpointID == authorization.DownstreamEndpointID {
		return ErrRelayDownstreamSelfAssignment
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var relayActive int
	err = tx.QueryRow(`SELECT 1 FROM endpoint_relay_authorizations r JOIN endpoints e ON e.id=r.endpoint_id
		WHERE r.endpoint_id=? AND r.status='active' AND e.status='active'`, authorization.RelayEndpointID).Scan(&relayActive)
	if err == sql.ErrNoRows {
		return ErrEndpointRelayUnavailable
	}
	if err != nil {
		return err
	}
	var downstreamStatus model.EndpointStatus
	if err := tx.QueryRow(`SELECT status FROM endpoints WHERE id=?`, authorization.DownstreamEndpointID).Scan(&downstreamStatus); err == sql.ErrNoRows {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	if downstreamStatus != model.EndpointActive {
		return ErrRelayDownstreamUnavailable
	}
	var existingID string
	if err := tx.QueryRow(`SELECT id FROM relay_downstream_authorizations WHERE downstream_endpoint_id=? AND status='active'`, authorization.DownstreamEndpointID).Scan(&existingID); err == nil {
		return ErrRelayDownstreamAlreadyActive
	} else if err != sql.ErrNoRows {
		return err
	}
	_, err = tx.Exec(`INSERT INTO relay_downstream_authorizations(id,relay_endpoint_id,downstream_endpoint_id,status,authorization_reason,authorized_by,authorized_at) VALUES(?,?,?,'active',?,?,?)`,
		authorization.ID, authorization.RelayEndpointID, authorization.DownstreamEndpointID, authorization.AuthorizationReason, authorization.AuthorizedBy, formatTime(authorization.AuthorizedAt))
	if err != nil {
		return err
	}
	if err := insertAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLiteStore) RevokeRelayDownstream(relayEndpointID, downstreamEndpointID, reason, actorID string, now time.Time, event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.Exec(`UPDATE relay_downstream_authorizations SET status='revoked',revocation_reason=?,revoked_by=?,revoked_at=?
		WHERE relay_endpoint_id=? AND downstream_endpoint_id=? AND status='active'`, reason, actorID, formatTime(now), relayEndpointID, downstreamEndpointID)
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

func (s *SQLiteStore) ListRelayDownstreamAuthorizations() ([]model.RelayDownstreamAuthorization, error) {
	rows, err := s.db.Query(`SELECT id,relay_endpoint_id,downstream_endpoint_id,status,authorization_reason,authorized_by,authorized_at,revocation_reason,revoked_by,revoked_at FROM relay_downstream_authorizations ORDER BY authorized_at DESC,id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	authorizations := []model.RelayDownstreamAuthorization{}
	for rows.Next() {
		var authorization model.RelayDownstreamAuthorization
		var authorizedAt string
		var revokedAt sql.NullString
		if err := rows.Scan(&authorization.ID, &authorization.RelayEndpointID, &authorization.DownstreamEndpointID, &authorization.Status,
			&authorization.AuthorizationReason, &authorization.AuthorizedBy, &authorizedAt, &authorization.RevocationReason, &authorization.RevokedBy, &revokedAt); err != nil {
			return nil, err
		}
		authorization.AuthorizedAt, _ = parseTime(authorizedAt)
		if revokedAt.Valid {
			value, _ := parseTime(revokedAt.String)
			authorization.RevokedAt = &value
		}
		authorizations = append(authorizations, authorization)
	}
	return authorizations, rows.Err()
}
