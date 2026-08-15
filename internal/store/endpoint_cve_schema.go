package store

import (
	"fmt"
	"time"
)

func (s *SQLiteStore) applyEndpointCVEMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin endpoint CVE migration: %w", err)
	}
	defer tx.Rollback()
	_, err = tx.Exec(`CREATE TABLE endpoint_cve_matches (
		endpoint_id TEXT NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,cve_id TEXT NOT NULL REFERENCES cves(id) ON DELETE CASCADE,
		product TEXT NOT NULL,version TEXT NOT NULL,package_source TEXT NOT NULL,confidence TEXT NOT NULL,evidence TEXT NOT NULL,matched_at TEXT NOT NULL,
		PRIMARY KEY(endpoint_id,cve_id,product,version,package_source))`)
	if err != nil {
		return fmt.Errorf("apply endpoint CVE migration: %w", err)
	}
	if _, err := tx.Exec(`CREATE INDEX endpoint_cve_matches_cve_idx ON endpoint_cve_matches(cve_id,endpoint_id)`); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(46,?)`, formatTime(time.Now().UTC())); err != nil {
		return err
	}
	return tx.Commit()
}
