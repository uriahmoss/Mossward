package store

import (
	"fmt"
	"time"
)

func (s *SQLiteStore) applyNotificationMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	statements := []string{
		`CREATE TABLE smtp_settings (id INTEGER PRIMARY KEY CHECK(id=1),enabled INTEGER NOT NULL,host TEXT NOT NULL,port INTEGER NOT NULL,username TEXT NOT NULL,password_ciphertext BLOB,from_address TEXT NOT NULL,tls_mode TEXT NOT NULL)`,
		`CREATE TABLE smtp_recipients (user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE)`,
		`CREATE TABLE scan_long_alerts (scan_id TEXT PRIMARY KEY,sent_at TEXT NOT NULL)`,
	}
	for _, statement := range statements {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("apply SMTP migration: %w", err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version,applied_at)VALUES(17,?)`, formatTime(time.Now().UTC())); err != nil {
		return err
	}
	return tx.Commit()
}
