package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"mossward/internal/model"
)

func (s *PostgreSQLStore) SaveFindingException(value model.FindingException, event model.AuditEvent) error {
	if value.ReminderDays < 1 || value.ReminderDays > 365 || value.Reason == "" ||
		(value.ExpiresAt != nil && !value.ExpiresAt.After(value.CreatedAt)) {
		return ErrInvalidFindingWorkflow
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL finding-exception update: %w", err)
	}
	defer tx.Rollback()
	var scanStatus model.ScanStatus
	err = tx.QueryRow(`SELECT s.status FROM findings f JOIN scans s ON s.id=f.scan_id WHERE f.id=$1`, value.FindingID).
		Scan(&scanStatus)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrFindingNotFound
	}
	if err != nil {
		return fmt.Errorf("validate PostgreSQL exception finding: %w", err)
	}
	if scanStatus != model.StatusCompleted {
		return ErrInvalidFindingWorkflow
	}
	_, err = tx.Exec(`INSERT INTO finding_exceptions(id,finding_id,reason,status,requested_by,created_at,expires_at,reminder_days)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, value.ID, value.FindingID, value.Reason, value.Status,
		value.RequestedBy, value.CreatedAt, value.ExpiresAt, value.ReminderDays)
	if err != nil {
		return fmt.Errorf("save PostgreSQL finding exception: %w", err)
	}
	if err := insertPostgreSQLAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgreSQLStore) ListFindingExceptions() ([]model.FindingException, error) {
	rows, err := s.db.Query(`SELECT id,finding_id,reason,status,requested_by,COALESCE(approved_by,''),created_at,
		expires_at,reminder_days,last_reminder_at FROM finding_exceptions ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list PostgreSQL finding exceptions: %w", err)
	}
	defer rows.Close()
	values := []model.FindingException{}
	for rows.Next() {
		var value model.FindingException
		var expiresAt, lastReminderAt sql.NullTime
		if err := rows.Scan(&value.ID, &value.FindingID, &value.Reason, &value.Status, &value.RequestedBy,
			&value.ApprovedBy, &value.CreatedAt, &expiresAt, &value.ReminderDays, &lastReminderAt); err != nil {
			return nil, fmt.Errorf("read PostgreSQL finding exception: %w", err)
		}
		value.ExpiresAt = nullablePostgreSQLTime(expiresAt)
		value.LastReminderAt = nullablePostgreSQLTime(lastReminderAt)
		values = append(values, value)
	}
	return values, rows.Err()
}

func (s *PostgreSQLStore) ReviewFindingException(id string, status model.FindingExceptionStatus, admin string, _ time.Time, event model.AuditEvent) error {
	if status != model.ExceptionApproved && status != model.ExceptionRejected {
		return ErrInvalidFindingWorkflow
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL finding-exception review: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.Exec(`UPDATE finding_exceptions SET status=$1,approved_by=$2 WHERE id=$3 AND status='pending'`,
		status, admin, id)
	if err != nil {
		return fmt.Errorf("review PostgreSQL finding exception: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed == 0 {
		return ErrFindingNotFound
	}
	if err := insertPostgreSQLAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgreSQLStore) EvidenceRetentionSettings() (model.EvidenceRetentionSettings, error) {
	var settings model.EvidenceRetentionSettings
	err := s.db.QueryRow(`SELECT retention_days,updated_at FROM evidence_retention_settings WHERE id=1`).
		Scan(&settings.RetentionDays, &settings.UpdatedAt)
	if err != nil {
		return settings, fmt.Errorf("load PostgreSQL evidence-retention settings: %w", err)
	}
	return settings, nil
}

func (s *PostgreSQLStore) SaveEvidenceRetentionSettings(settings model.EvidenceRetentionSettings, event model.AuditEvent) error {
	if settings.RetentionDays < 30 || settings.RetentionDays > 3650 {
		return ErrInvalidFindingWorkflow
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL evidence-retention update: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE evidence_retention_settings SET retention_days=$1,updated_at=$2 WHERE id=1`,
		settings.RetentionDays, settings.UpdatedAt); err != nil {
		return fmt.Errorf("update PostgreSQL evidence-retention settings: %w", err)
	}
	if err := insertPostgreSQLAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgreSQLStore) PurgeExpiredEvidence(now time.Time) (int64, error) {
	result, err := s.db.Exec(`DELETE FROM scans WHERE completed_at IS NOT NULL
		AND completed_at < ($1-(SELECT retention_days FROM evidence_retention_settings WHERE id=1)*INTERVAL '1 day')
		AND NOT EXISTS(SELECT 1 FROM findings f JOIN finding_exceptions e ON e.finding_id=f.id
			WHERE f.scan_id=scans.id AND e.status='approved' AND (e.expires_at IS NULL OR e.expires_at>$1))`, now)
	if err != nil {
		return 0, fmt.Errorf("purge expired PostgreSQL evidence: %w", err)
	}
	return result.RowsAffected()
}

func (s *PostgreSQLStore) DueOpenEndedExceptions(now time.Time) ([]model.FindingException, error) {
	values, err := s.ListFindingExceptions()
	if err != nil {
		return nil, err
	}
	due := values[:0]
	for _, value := range values {
		if value.Status != model.ExceptionApproved || value.ExpiresAt != nil {
			continue
		}
		lastReminder := value.CreatedAt
		if value.LastReminderAt != nil {
			lastReminder = *value.LastReminderAt
		}
		if !lastReminder.AddDate(0, 0, value.ReminderDays).After(now) {
			due = append(due, value)
		}
	}
	return due, nil
}

func (s *PostgreSQLStore) MarkExceptionReminded(id string, now time.Time) error {
	_, err := s.db.Exec(`UPDATE finding_exceptions SET last_reminder_at=$1 WHERE id=$2`, now, id)
	if err != nil {
		return fmt.Errorf("mark PostgreSQL finding exception reminded: %w", err)
	}
	return nil
}
