package store

import (
	"fmt"
	"time"
)

func (s *SQLiteStore) applyAssetAgentEligibilityMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin asset agent-eligibility migration: %w", err)
	}
	defer tx.Rollback()
	for _, statement := range []string{
		`ALTER TABLE assets ADD COLUMN agent_eligibility TEXT NOT NULL DEFAULT 'unknown' CHECK(agent_eligibility IN ('unknown','eligible','ineligible'))`,
		`ALTER TABLE assets ADD COLUMN agent_eligibility_reason TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE assets ADD COLUMN agent_eligibility_updated_by TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE assets ADD COLUMN agent_eligibility_updated_at TEXT`,
	} {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("apply asset agent-eligibility migration: %w", err)
		}
	}
	if _, err := tx.Exec(`CREATE INDEX asset_agent_eligibility_idx ON assets(agent_eligibility,lifecycle_status,last_seen)`); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(54,?)`, formatTime(time.Now().UTC())); err != nil {
		return err
	}
	return tx.Commit()
}
