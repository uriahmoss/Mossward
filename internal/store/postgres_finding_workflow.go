package store

import (
	"fmt"
	"time"

	"mossward/internal/model"
)

func (s *PostgreSQLStore) UpdateFindingWorkflow(id string, update model.FindingWorkflowUpdate, now time.Time, event model.AuditEvent) error {
	if !validFindingStatus(update.Status) {
		return ErrInvalidFindingWorkflow
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL finding workflow update: %w", err)
	}
	defer tx.Rollback()
	if update.AssignedTo != "" {
		var activeUsers int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM users WHERE id=$1 AND status='active'`, update.AssignedTo).Scan(&activeUsers); err != nil {
			return fmt.Errorf("validate PostgreSQL finding assignee: %w", err)
		}
		if activeUsers != 1 {
			return ErrInvalidFindingWorkflow
		}
	}
	result, err := tx.Exec(`UPDATE findings SET status=$1,assigned_to=NULLIF($2,''),workflow_updated_at=$3 WHERE id=$4`,
		update.Status, update.AssignedTo, now, id)
	if err != nil {
		return fmt.Errorf("update PostgreSQL finding workflow: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read PostgreSQL finding workflow result: %w", err)
	}
	if changed == 0 {
		return ErrFindingNotFound
	}
	if err := insertPostgreSQLAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}
