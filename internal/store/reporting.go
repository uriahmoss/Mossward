package store

import (
	"database/sql"
	"fmt"
	"mossward/internal/model"
	"time"
)

func (s *SQLiteStore) applyReportingMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	statements := []string{
		`CREATE TABLE finding_exceptions(id TEXT PRIMARY KEY,finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,reason TEXT NOT NULL,status TEXT NOT NULL CHECK(status IN ('pending','approved','rejected')),requested_by TEXT NOT NULL REFERENCES users(id),approved_by TEXT REFERENCES users(id),created_at TEXT NOT NULL,expires_at TEXT,reminder_days INTEGER NOT NULL DEFAULT 30 CHECK(reminder_days BETWEEN 1 AND 365),last_reminder_at TEXT)`,
		`CREATE INDEX finding_exceptions_due_idx ON finding_exceptions(status,expires_at,last_reminder_at)`,
		`CREATE TABLE evidence_retention_settings(id INTEGER PRIMARY KEY CHECK(id=1),retention_days INTEGER NOT NULL CHECK(retention_days BETWEEN 30 AND 3650),updated_at TEXT NOT NULL)`,
	}
	for _, statement := range statements {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("apply reporting migration: %w", err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO evidence_retention_settings(id,retention_days,updated_at) VALUES(1,365,?)`, formatTime(time.Now().UTC())); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(37,?)`, formatTime(time.Now().UTC())); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLiteStore) SaveFindingException(value model.FindingException, event model.AuditEvent) error {
	if value.ReminderDays < 1 || value.ReminderDays > 365 || value.Reason == "" ||
		(value.ExpiresAt != nil && !value.ExpiresAt.After(value.CreatedAt)) {
		return ErrInvalidFindingWorkflow
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var scanStatus model.ScanStatus
	if err := tx.QueryRow(`SELECT s.status FROM findings f JOIN scans s ON s.id=f.scan_id WHERE f.id=?`, value.FindingID).Scan(&scanStatus); err != nil {
		return ErrFindingNotFound
	}
	if scanStatus != model.StatusCompleted {
		return ErrInvalidFindingWorkflow
	}
	_, err = tx.Exec(`INSERT INTO finding_exceptions(id,finding_id,reason,status,requested_by,created_at,expires_at,reminder_days) VALUES(?,?,?,?,?,?,?,?)`, value.ID, value.FindingID, value.Reason, value.Status, value.RequestedBy, formatTime(value.CreatedAt), formatOptionalTime(value.ExpiresAt), value.ReminderDays)
	if err != nil {
		return fmt.Errorf("save finding exception: %w", err)
	}
	if err := insertAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *SQLiteStore) ListFindingExceptions() ([]model.FindingException, error) {
	rows, err := s.db.Query(`SELECT id,finding_id,reason,status,requested_by,COALESCE(approved_by,''),created_at,expires_at,reminder_days,last_reminder_at FROM finding_exceptions ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []model.FindingException
	for rows.Next() {
		var v model.FindingException
		var created string
		var expires, last sql.NullString
		if err := rows.Scan(&v.ID, &v.FindingID, &v.Reason, &v.Status, &v.RequestedBy, &v.ApprovedBy, &created, &expires, &v.ReminderDays, &last); err != nil {
			return nil, err
		}
		v.CreatedAt, _ = parseTime(created)
		if expires.Valid {
			x, _ := parseTime(expires.String)
			v.ExpiresAt = &x
		}
		if last.Valid {
			x, _ := parseTime(last.String)
			v.LastReminderAt = &x
		}
		values = append(values, v)
	}
	return values, rows.Err()
}
func (s *SQLiteStore) ReviewFindingException(id string, status model.FindingExceptionStatus, admin string, now time.Time, event model.AuditEvent) error {
	if status != model.ExceptionApproved && status != model.ExceptionRejected {
		return ErrInvalidFindingWorkflow
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.Exec(`UPDATE finding_exceptions SET status=?,approved_by=? WHERE id=? AND status='pending'`, status, admin, id)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return ErrFindingNotFound
	}
	if err := insertAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *SQLiteStore) EvidenceRetentionSettings() (model.EvidenceRetentionSettings, error) {
	var v model.EvidenceRetentionSettings
	var updated string
	err := s.db.QueryRow(`SELECT retention_days,updated_at FROM evidence_retention_settings WHERE id=1`).Scan(&v.RetentionDays, &updated)
	v.UpdatedAt, _ = parseTime(updated)
	return v, err
}
func (s *SQLiteStore) SaveEvidenceRetentionSettings(v model.EvidenceRetentionSettings, event model.AuditEvent) error {
	if v.RetentionDays < 30 || v.RetentionDays > 3650 {
		return ErrInvalidFindingWorkflow
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.Exec(`UPDATE evidence_retention_settings SET retention_days=?,updated_at=? WHERE id=1`, v.RetentionDays, formatTime(v.UpdatedAt))
	if err != nil {
		return err
	}
	if err = insertAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *SQLiteStore) PurgeExpiredEvidence(now time.Time) (int64, error) {
	settings, err := s.EvidenceRetentionSettings()
	if err != nil {
		return 0, err
	}
	cutoff := now.AddDate(0, 0, -settings.RetentionDays)
	result, err := s.db.Exec(`DELETE FROM scans WHERE completed_at IS NOT NULL AND completed_at<? AND NOT EXISTS(SELECT 1 FROM findings f JOIN finding_exceptions e ON e.finding_id=f.id WHERE f.scan_id=scans.id AND e.status='approved' AND (e.expires_at IS NULL OR e.expires_at>?))`, formatTime(cutoff), formatTime(now))
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}
func (s *SQLiteStore) DueOpenEndedExceptions(now time.Time) ([]model.FindingException, error) {
	values, err := s.ListFindingExceptions()
	if err != nil {
		return nil, err
	}
	due := values[:0]
	for _, v := range values {
		if v.Status != model.ExceptionApproved || v.ExpiresAt != nil {
			continue
		}
		last := v.CreatedAt
		if v.LastReminderAt != nil {
			last = *v.LastReminderAt
		}
		if !last.AddDate(0, 0, v.ReminderDays).After(now) {
			due = append(due, v)
		}
	}
	return due, nil
}
func (s *SQLiteStore) MarkExceptionReminded(id string, now time.Time) error {
	_, err := s.db.Exec(`UPDATE finding_exceptions SET last_reminder_at=? WHERE id=?`, formatTime(now), id)
	return err
}
