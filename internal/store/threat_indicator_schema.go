package store

import (
	"fmt"
	"time"
)

func (s *SQLiteStore) applyThreatIndicatorMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin threat indicator migration: %w", err)
	}
	defer tx.Rollback()
	statements := []string{
		`CREATE TABLE threat_indicators (id TEXT PRIMARY KEY, type TEXT NOT NULL CHECK(type IN ('ip','hostname')), value TEXT NOT NULL, source TEXT NOT NULL, confidence TEXT NOT NULL CHECK(confidence IN ('low','medium','high')), observed_at TEXT NOT NULL, expires_at TEXT NOT NULL, enabled INTEGER NOT NULL, created_by TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, UNIQUE(type,value,source))`,
		`CREATE INDEX idx_threat_indicators_active ON threat_indicators(enabled,expires_at,type,value)`,
		`CREATE TABLE endpoint_indicator_matches (endpoint_id TEXT NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE, indicator_id TEXT NOT NULL REFERENCES threat_indicators(id) ON DELETE CASCADE, connection_ordinal INTEGER NOT NULL, matched_at TEXT NOT NULL, PRIMARY KEY(endpoint_id,indicator_id,connection_ordinal))`,
		`CREATE INDEX idx_endpoint_indicator_matches_endpoint ON endpoint_indicator_matches(endpoint_id,matched_at)`,
	}
	for _, statement := range statements {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("apply threat indicator migration: %w", err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(50,?)`, formatTime(time.Now().UTC())); err != nil {
		return err
	}
	return tx.Commit()
}
