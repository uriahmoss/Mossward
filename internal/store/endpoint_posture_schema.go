package store

import (
	"fmt"
	"time"
)

func (s *SQLiteStore) applyEndpointPostureMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin endpoint posture migration: %w", err)
	}
	defer tx.Rollback()
	statements := []string{
		`CREATE TABLE endpoint_posture_inventory (endpoint_id TEXT PRIMARY KEY REFERENCES endpoints(id) ON DELETE CASCADE,collected_at TEXT NOT NULL,received_at TEXT NOT NULL)`,
		`CREATE TABLE endpoint_posture_evidence (endpoint_id TEXT NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,evidence_id TEXT NOT NULL,title TEXT NOT NULL,status TEXT NOT NULL CHECK(status IN ('pass','fail','unknown')),detail TEXT NOT NULL,PRIMARY KEY(endpoint_id,evidence_id))`,
		`CREATE INDEX endpoint_posture_status_idx ON endpoint_posture_evidence(status,evidence_id)`,
	}
	for _, statement := range statements {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("apply endpoint posture migration: %w", err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(45,?)`, formatTime(time.Now().UTC())); err != nil {
		return err
	}
	return tx.Commit()
}
