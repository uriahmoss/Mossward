package store

import (
	"fmt"
	"time"

	"mossward/internal/model"
)

func (s *SQLiteStore) applyFindingWorkflowMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin finding workflow migration: %w", err)
	}
	defer tx.Rollback()
	for _, statement := range []string{
		`ALTER TABLE findings ADD COLUMN status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','in_progress','resolved'))`,
		`ALTER TABLE findings ADD COLUMN assigned_to TEXT`,
		`ALTER TABLE findings ADD COLUMN workflow_updated_at TEXT`,
		`CREATE INDEX findings_workflow_idx ON findings(status,assigned_to)`,
	} {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("apply finding workflow migration: %w", err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(36,?)`, formatTime(time.Now().UTC())); err != nil {
		return fmt.Errorf("record finding workflow migration: %w", err)
	}
	return tx.Commit()
}

func (s *SQLiteStore) UpdateFindingWorkflow(id string, update model.FindingWorkflowUpdate, now time.Time, event model.AuditEvent) error {
	if !validFindingStatus(update.Status) {
		return ErrInvalidFindingWorkflow
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin finding workflow update: %w", err)
	}
	defer tx.Rollback()
	if update.AssignedTo != "" {
		var count int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM users WHERE id=? AND status='active'`, update.AssignedTo).Scan(&count); err != nil || count != 1 {
			return ErrInvalidFindingWorkflow
		}
	}
	result, err := tx.Exec(`UPDATE findings SET status=?,assigned_to=NULLIF(?,''),workflow_updated_at=? WHERE id=?`, update.Status, update.AssignedTo, formatTime(now), id)
	if err != nil {
		return fmt.Errorf("update finding workflow: %w", err)
	}
	changed, _ := result.RowsAffected()
	if changed == 0 {
		return ErrFindingNotFound
	}
	if err := insertAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func validFindingStatus(status model.FindingStatus) bool {
	return status == model.FindingOpen || status == model.FindingInProgress || status == model.FindingResolved
}
func defaultFindingStatus(status model.FindingStatus) model.FindingStatus {
	if status == "" {
		return model.FindingOpen
	}
	return status
}
