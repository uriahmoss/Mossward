package store

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"mossward/internal/model"
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

func TestScopePoliciesCannotCrossInstallationOrganization(t *testing.T) {
	repository := openTestStore(t)
	organization, err := repository.Organization()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	policy := model.ScopePolicy{ID: "organization-scope", Name: "Organization scope", AllowedCIDRs: []string{"192.0.2.0/24"},
		AllowedPorts: []int{443}, MaxTargets: 10, MaxConcurrent: 2, Enabled: true, CreatedAt: now, UpdatedAt: now}
	event := model.AuditEvent{OccurredAt: now, Action: "scope.organization", Severity: model.AuditInfo}
	if err := repository.UpsertScopePolicy(policy, event); err != nil {
		t.Fatal(err)
	}
	loaded, err := repository.ScopePolicy(policy.ID)
	if err != nil || loaded.OrganizationID != organization.ID {
		t.Fatalf("organization scope policy = %#v, error = %v", loaded, err)
	}
	if _, err := repository.db.Exec(`UPDATE scope_policies SET organization_id='different-installation' WHERE id=?`, policy.ID); err == nil {
		t.Fatal("scope policy was moved across organizations")
	}
	if _, err := repository.db.Exec(`INSERT INTO scope_policies(id,name,allowed_cidrs,allowed_ports,max_targets,max_concurrent,enabled,created_at,updated_at,organization_id) VALUES('foreign','Foreign','[]','[]',1,1,1,?,?,?)`,
		formatTime(now), formatTime(now), "different-installation"); err == nil {
		t.Fatal("foreign organization scope policy was inserted")
	}
}
