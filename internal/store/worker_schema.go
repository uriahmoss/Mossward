package store

import (
	"fmt"
	"time"
)

func (s *SQLiteStore) applyScannerWorkerIdentityMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin scanner-worker identity migration: %w", err)
	}
	defer tx.Rollback()
	statements := []string{
		`CREATE TABLE scanner_worker_enrollment_tokens (id TEXT PRIMARY KEY,name TEXT NOT NULL,token_hash BLOB NOT NULL UNIQUE,allowed_cidrs TEXT NOT NULL,allowed_ports TEXT NOT NULL,max_concurrent INTEGER NOT NULL CHECK(max_concurrent BETWEEN 1 AND 256),rate_limit_per_second INTEGER NOT NULL CHECK(rate_limit_per_second BETWEEN 0 AND 1000),created_by TEXT NOT NULL REFERENCES users(id),created_at TEXT NOT NULL,expires_at TEXT NOT NULL,used_at TEXT)`,
		`CREATE INDEX scanner_worker_tokens_expiry_idx ON scanner_worker_enrollment_tokens(expires_at,used_at)`,
		`CREATE TABLE scanner_workers (id TEXT PRIMARY KEY,name TEXT NOT NULL,status TEXT NOT NULL CHECK(status IN ('active','revoked')),certificate_serial TEXT NOT NULL UNIQUE,certificate_pem TEXT NOT NULL,allowed_cidrs TEXT NOT NULL,allowed_ports TEXT NOT NULL,max_concurrent INTEGER NOT NULL CHECK(max_concurrent BETWEEN 1 AND 256),rate_limit_per_second INTEGER NOT NULL CHECK(rate_limit_per_second BETWEEN 0 AND 1000),enrolled_at TEXT NOT NULL,expires_at TEXT NOT NULL,last_seen_at TEXT,revoked_at TEXT,revocation_reason TEXT NOT NULL DEFAULT '')`,
		`CREATE INDEX scanner_workers_status_idx ON scanner_workers(status,name)`,
	}
	for _, statement := range statements {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("apply scanner-worker identity migration: %w", err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(22,?)`, formatTime(time.Now().UTC())); err != nil {
		return fmt.Errorf("record scanner-worker identity migration: %w", err)
	}
	return tx.Commit()
}
