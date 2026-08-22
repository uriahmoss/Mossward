package store

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestInstallationOrganizationIsStableAndEnforced(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mossward.db")
	repository, err := NewSQLiteStore(path, "")
	if err != nil {
		t.Fatal(err)
	}
	organization, err := repository.Organization()
	if err != nil || organization.ID == "" || organization.Name != defaultOrganizationName || organization.CreatedAt.IsZero() {
		t.Fatalf("installation organization = %#v, error = %v", organization, err)
	}
	if err := repository.RequireOrganization(organization.ID); err != nil {
		t.Fatal(err)
	}
	if err := repository.RequireOrganization("different-installation"); !errors.Is(err, ErrOrganizationBoundary) {
		t.Fatalf("cross-organization identity result = %v", err)
	}
	if _, err := repository.db.Exec(`UPDATE installation_organization SET id='changed'`); err == nil {
		t.Fatal("immutable organization identity was changed")
	}
	if _, err := repository.db.Exec(`DELETE FROM installation_organization`); err == nil {
		t.Fatal("installation organization was deleted")
	}
	if err := repository.Close(); err != nil {
		t.Fatal(err)
	}
	repository, err = NewSQLiteStore(path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	reopened, err := repository.Organization()
	if err != nil || reopened.ID != organization.ID {
		t.Fatalf("reopened organization = %#v, error = %v", reopened, err)
	}
}
