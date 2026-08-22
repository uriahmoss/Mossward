package store

import (
	"database/sql"
	"errors"
	"fmt"

	"mossward/internal/model"
)

var ErrOrganizationBoundary = errors.New("Mossward installation organization boundary is invalid")

func (s *SQLiteStore) Organization() (model.Organization, error) {
	var organization model.Organization
	var createdAt string
	err := s.db.QueryRow(`SELECT id,name,created_at FROM installation_organization LIMIT 1`).
		Scan(&organization.ID, &organization.Name, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return organization, ErrOrganizationBoundary
	}
	if err != nil {
		return organization, fmt.Errorf("read installation organization: %w", err)
	}
	organization.CreatedAt, err = parseTime(createdAt)
	if err != nil || organization.ID == "" || organization.Name == "" {
		return model.Organization{}, ErrOrganizationBoundary
	}
	return organization, nil
}

func (s *SQLiteStore) RequireOrganization(id string) error {
	organization, err := s.Organization()
	if err != nil {
		return err
	}
	if id == "" || id != organization.ID {
		return ErrOrganizationBoundary
	}
	return nil
}
