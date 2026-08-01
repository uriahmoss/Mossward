package store

import (
	"fmt"
	"time"
)

func (s *SQLiteStore) applyAssetInventoryMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin asset inventory migration: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`CREATE TABLE assets (
		id TEXT PRIMARY KEY, name TEXT NOT NULL, address TEXT NOT NULL UNIQUE,
		first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, last_scan_id TEXT NOT NULL
	)`); err != nil {
		return fmt.Errorf("apply asset inventory migration: %w", err)
	}
	if _, err := tx.Exec(`CREATE INDEX assets_last_seen_idx ON assets(last_seen DESC)`); err != nil {
		return fmt.Errorf("index asset inventory: %w", err)
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version, applied_at) VALUES(11, ?)`, formatTime(time.Now().UTC())); err != nil {
		return fmt.Errorf("record asset inventory migration: %w", err)
	}
	return tx.Commit()
}

func (s *SQLiteStore) applyAssetMetadataMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin asset metadata migration: %w", err)
	}
	defer tx.Rollback()
	for _, statement := range []string{
		`ALTER TABLE assets ADD COLUMN owner TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE assets ADD COLUMN environment TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE assets ADD COLUMN classification TEXT NOT NULL DEFAULT ''`,
	} {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("apply asset metadata migration: %w", err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version, applied_at) VALUES(13, ?)`, formatTime(time.Now().UTC())); err != nil {
		return fmt.Errorf("record asset metadata migration: %w", err)
	}
	return tx.Commit()
}

func (s *SQLiteStore) applyAssetCorrelationMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin asset correlation migration: %w", err)
	}
	defer tx.Rollback()
	statements := []string{
		`CREATE TABLE asset_addresses (
			asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
			address TEXT NOT NULL UNIQUE, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
			last_scan_id TEXT NOT NULL, PRIMARY KEY(asset_id,address)
		)`,
		`CREATE INDEX asset_addresses_asset_idx ON asset_addresses(asset_id,last_seen DESC)`,
		`CREATE TABLE asset_names (
			asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
			name TEXT NOT NULL, normalized_name TEXT NOT NULL UNIQUE,
			PRIMARY KEY(asset_id,normalized_name)
		)`,
		`CREATE INDEX asset_names_asset_idx ON asset_names(asset_id,name)`,
		`INSERT INTO asset_addresses(asset_id,address,first_seen,last_seen,last_scan_id)
			SELECT id,address,first_seen,last_seen,last_scan_id FROM assets`,
	}
	for _, statement := range statements {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("apply asset correlation migration: %w", err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version, applied_at) VALUES(12, ?)`, formatTime(time.Now().UTC())); err != nil {
		return fmt.Errorf("record asset correlation migration: %w", err)
	}
	return tx.Commit()
}
