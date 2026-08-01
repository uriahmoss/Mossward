package store

import (
	"fmt"
	"time"
)

func (s *SQLiteStore) applyAssetServiceHistoryMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin asset service history migration: %w", err)
	}
	defer tx.Rollback()
	statements := []string{`CREATE TABLE asset_services (asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,address TEXT NOT NULL,port INTEGER NOT NULL,protocol TEXT NOT NULL,product TEXT NOT NULL DEFAULT '',version TEXT NOT NULL DEFAULT '',confidence TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('observed','not_observed')),first_seen TEXT NOT NULL,last_seen TEXT NOT NULL,last_checked TEXT NOT NULL,last_scan_id TEXT NOT NULL,observation_count INTEGER NOT NULL,PRIMARY KEY(asset_id,address,port,protocol))`, `CREATE INDEX asset_services_asset_state_idx ON asset_services(asset_id,state,last_seen DESC)`, `CREATE TABLE asset_service_events (observation_id TEXT PRIMARY KEY,asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,scan_id TEXT NOT NULL,address TEXT NOT NULL,port INTEGER NOT NULL,protocol TEXT NOT NULL,product TEXT NOT NULL DEFAULT '',version TEXT NOT NULL DEFAULT '',confidence TEXT NOT NULL,observed_at TEXT NOT NULL,finding_ids TEXT NOT NULL DEFAULT '[]',cve_ids TEXT NOT NULL DEFAULT '[]')`, `CREATE INDEX asset_service_events_lookup_idx ON asset_service_events(asset_id,address,port,protocol,observed_at DESC)`}
	for _, statement := range statements {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("apply asset service history migration: %w", err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version,applied_at)VALUES(18,?)`, formatTime(time.Now().UTC())); err != nil {
		return err
	}
	return tx.Commit()
}
