package store

import (
	"fmt"
	"time"
)

func (s *SQLiteStore) applyEvidenceProvenanceMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin evidence provenance migration: %w", err)
	}
	defer tx.Rollback()
	statements := []string{
		`ALTER TABLE asset_service_events ADD COLUMN source_type TEXT NOT NULL DEFAULT 'scanner' CHECK(source_type IN ('scanner','endpoint'))`,
		`ALTER TABLE asset_service_events ADD COLUMN source_id TEXT NOT NULL DEFAULT 'scanner/local'`,
		`CREATE TABLE asset_evidence (id TEXT PRIMARY KEY,asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,source_type TEXT NOT NULL CHECK(source_type IN ('scanner','endpoint')),source_id TEXT NOT NULL,record_type TEXT NOT NULL,record_id TEXT NOT NULL,scan_id TEXT NOT NULL DEFAULT '',address TEXT NOT NULL DEFAULT '',summary TEXT NOT NULL,collected_at TEXT NOT NULL,UNIQUE(source_type,source_id,record_type,record_id))`,
		`CREATE INDEX asset_evidence_asset_time_idx ON asset_evidence(asset_id,collected_at DESC)`,
		`INSERT INTO asset_evidence(id,asset_id,source_type,source_id,record_type,record_id,scan_id,address,summary,collected_at) SELECT 'scanner:'||observation_id,asset_id,'scanner','scanner/local','service_observation',observation_id,scan_id,address,protocol||' service observed on port '||port,observed_at FROM asset_service_events`,
	}
	for _, statement := range statements {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("apply evidence provenance migration: %w", err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version,applied_at)VALUES(19,?)`, formatTime(time.Now().UTC())); err != nil {
		return err
	}
	return tx.Commit()
}
