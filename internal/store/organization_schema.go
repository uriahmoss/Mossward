package store

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

const (
	organizationIDBytes     = 16
	defaultOrganizationName = "Mossward organization"
)

func (s *SQLiteStore) applyOrganizationBoundaryMigration() error {
	organizationID, err := newOrganizationID()
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin organization-boundary migration: %w", err)
	}
	defer tx.Rollback()
	statements := []string{
		`CREATE TABLE installation_organization (
			singleton INTEGER PRIMARY KEY CHECK(singleton=1),
			id TEXT NOT NULL UNIQUE,
			name TEXT NOT NULL,
			created_at TEXT NOT NULL
		)`,
		`INSERT INTO installation_organization(singleton,id,name,created_at) VALUES(1,?,?,?)`,
		`CREATE TRIGGER installation_organization_no_delete BEFORE DELETE ON installation_organization BEGIN SELECT RAISE(ABORT,'organization identity cannot be deleted'); END`,
		`CREATE TRIGGER installation_organization_id_immutable BEFORE UPDATE OF id ON installation_organization BEGIN SELECT RAISE(ABORT,'organization identity cannot be changed'); END`,
	}
	if _, err := tx.Exec(statements[0]); err != nil {
		return fmt.Errorf("create installation organization: %w", err)
	}
	if _, err := tx.Exec(statements[1], organizationID, defaultOrganizationName, formatTime(time.Now().UTC())); err != nil {
		return fmt.Errorf("initialize installation organization: %w", err)
	}
	for _, statement := range statements[2:] {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("protect installation organization: %w", err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(65,?)`, formatTime(time.Now().UTC())); err != nil {
		return fmt.Errorf("record organization-boundary migration: %w", err)
	}
	return tx.Commit()
}

func newOrganizationID() (string, error) {
	value := make([]byte, organizationIDBytes)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("create installation organization identity: %w", err)
	}
	return hex.EncodeToString(value), nil
}
