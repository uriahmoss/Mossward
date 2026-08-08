package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"mossward/internal/model"
)

func (s *SQLiteStore) AssignAgentUpdate(endpointID, releaseID, actorID string, assignedAt time.Time, event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var endpointOS, endpointArchitecture, releaseOS, releaseArchitecture string
	if err := tx.QueryRow(`SELECT operating_system,architecture FROM endpoints WHERE id=? AND status='active'`, endpointID).Scan(&endpointOS, &endpointArchitecture); err != nil {
		return ErrNotFound
	}
	if endpointOS == "" || endpointArchitecture == "" {
		return errors.New("endpoint must check in before an update can be assigned")
	}
	if err := tx.QueryRow(`SELECT operating_system,architecture FROM agent_update_releases WHERE id=? AND status='approved'`, releaseID).Scan(&releaseOS, &releaseArchitecture); err != nil {
		return ErrNotFound
	}
	if endpointOS != releaseOS || endpointArchitecture != releaseArchitecture {
		return errors.New("endpoint and update release platforms do not match")
	}
	_, err = tx.Exec(`INSERT INTO agent_update_assignments(endpoint_id,release_id,status,assigned_by,assigned_at)
		VALUES(?,?,'assigned',?,?) ON CONFLICT(endpoint_id) DO UPDATE SET release_id=excluded.release_id,status='assigned',assigned_by=excluded.assigned_by,assigned_at=excluded.assigned_at,offered_at=NULL,installed_at=NULL`,
		endpointID, releaseID, actorID, formatTime(assignedAt))
	if err != nil {
		return fmt.Errorf("assign endpoint-agent update: %w", err)
	}
	if err := insertAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLiteStore) AgentUpdateOffer(endpointID string, offeredAt time.Time) ([]byte, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var envelope []byte
	err = tx.QueryRow(`SELECT r.envelope FROM agent_update_assignments a JOIN agent_update_releases r ON r.id=a.release_id
		JOIN endpoints e ON e.id=a.endpoint_id WHERE a.endpoint_id=? AND a.status IN ('assigned','offered')
		AND r.status='approved' AND e.status='active' AND r.operating_system=e.operating_system AND r.architecture=e.architecture`, endpointID).Scan(&envelope)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(`UPDATE agent_update_assignments SET status='offered',offered_at=COALESCE(offered_at,?) WHERE endpoint_id=?`, formatTime(offeredAt), endpointID); err != nil {
		return nil, err
	}
	return envelope, tx.Commit()
}
