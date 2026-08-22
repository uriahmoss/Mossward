package store

import (
	"fmt"
	"time"
)

func (s *SQLiteStore) applyOrganizationScopePolicyMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin organization scope-policy migration: %w", err)
	}
	defer tx.Rollback()
	statements := []string{
		`ALTER TABLE scope_policies ADD COLUMN organization_id TEXT NOT NULL DEFAULT ''`,
		`UPDATE scope_policies SET organization_id=(SELECT id FROM installation_organization WHERE singleton=1)`,
		`CREATE INDEX scope_policies_organization_idx ON scope_policies(organization_id,name)`,
		`CREATE TRIGGER scope_policies_organization_insert BEFORE INSERT ON scope_policies
			WHEN NEW.organization_id<>(SELECT id FROM installation_organization WHERE singleton=1)
			BEGIN SELECT RAISE(ABORT,'scope policy organization mismatch'); END`,
		`CREATE TRIGGER scope_policies_organization_update BEFORE UPDATE OF organization_id ON scope_policies
			WHEN NEW.organization_id<>OLD.organization_id OR NEW.organization_id<>(SELECT id FROM installation_organization WHERE singleton=1)
			BEGIN SELECT RAISE(ABORT,'scope policy organization is immutable'); END`,
	}
	for _, statement := range statements {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("apply organization scope-policy migration: %w", err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(66,?)`, formatTime(time.Now().UTC())); err != nil {
		return fmt.Errorf("record organization scope-policy migration: %w", err)
	}
	return tx.Commit()
}
