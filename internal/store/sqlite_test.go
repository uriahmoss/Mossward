package store

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mossward/internal/model"
)

func openTestStore(t *testing.T) *SQLiteStore {
	t.Helper()
	repository, err := NewSQLiteStore(filepath.Join(t.TempDir(), "mossward.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := repository.Close(); err != nil {
			t.Errorf("close test database: %v", err)
		}
	})
	return repository
}

func TestSQLiteStoreRoundTrip(t *testing.T) {
	repository := openTestStore(t)
	started := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	completed := time.Now().UTC().Truncate(time.Microsecond)
	original := model.Scan{
		ID: "round-trip", Name: "Full scan", Status: model.StatusCompleted,
		Targets: []model.Target{{Name: "host.internal", Address: "127.0.0.1"}},
		Ports:   []int{80, 443}, TotalChecks: 2, DoneChecks: 2,
		CreatedAt: started, StartedAt: &started, CompletedAt: &completed,
		Observations: []model.ServiceObservation{{
			ID: "service", Target: "host.internal", Address: "127.0.0.1", Port: 80,
			Protocol: "http", Product: "nginx", Version: "1.25", Confidence: "high",
			Evidence: "HTTP 200", Metadata: map[string]string{"title": "Home"}, ObservedAt: completed,
		}},
		Findings: []model.Finding{{
			ID: "finding", CheckID: "http.cleartext", Target: "host.internal",
			Address: "127.0.0.1", Port: 80, Service: "http", Severity: "medium",
			Title: "Cleartext HTTP", Evidence: "HTTP response", Remediation: "Use HTTPS",
			ObservedAt: completed,
		}},
	}
	if err := repository.Save(original); err != nil {
		t.Fatal(err)
	}
	loaded, err := repository.Get(original.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Name != original.Name || len(loaded.Targets) != 1 || len(loaded.Ports) != 2 ||
		len(loaded.Observations) != 1 || len(loaded.Findings) != 1 ||
		loaded.Observations[0].Metadata["title"] != "Home" {
		t.Fatalf("scan did not round-trip through SQLite: %#v", loaded)
	}
	if !loaded.StartedAt.Equal(started) || !loaded.CompletedAt.Equal(completed) {
		t.Fatalf("timestamps did not round-trip: %#v", loaded)
	}
}

func TestSQLiteStoreReconcileInterrupted(t *testing.T) {
	repository := openTestStore(t)
	scan := model.Scan{
		ID: "queued-scan", Name: "queued", Status: model.StatusQueued,
		CreatedAt: time.Now().UTC(),
	}
	if err := repository.Save(scan); err != nil {
		t.Fatal(err)
	}
	if err := repository.ReconcileInterrupted(); err != nil {
		t.Fatal(err)
	}
	reconciled, err := repository.Get(scan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if reconciled.Status != model.StatusFailed || reconciled.CompletedAt == nil ||
		!strings.Contains(reconciled.Error, "interrupted") {
		t.Fatalf("missing interruption state: %#v", reconciled)
	}
}

func TestSQLiteDatabaseUsesOwnerOnlyPermissions(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "mossward.db")
	repository, err := NewSQLiteStore(path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected 0600 permissions, got %o", info.Mode().Perm())
	}
}

func TestSQLiteStoreReturnsIndependentValues(t *testing.T) {
	repository := openTestStore(t)
	original := model.Scan{
		ID: "copy-test", Status: model.StatusCompleted, CreatedAt: time.Now().UTC(),
		Targets:  []model.Target{{Name: "host", Address: "127.0.0.1"}},
		Ports:    []int{80},
		Findings: []model.Finding{{ID: "finding", ObservedAt: time.Now().UTC()}},
		Observations: []model.ServiceObservation{{
			ID: "service", Metadata: map[string]string{"server": "nginx"}, ObservedAt: time.Now().UTC(),
		}},
	}
	if err := repository.Save(original); err != nil {
		t.Fatal(err)
	}
	loaded, err := repository.Get(original.ID)
	if err != nil {
		t.Fatal(err)
	}
	loaded.Targets[0].Name = "changed"
	loaded.Ports[0] = 443
	loaded.Findings[0].ID = "changed"
	loaded.Observations[0].Metadata["server"] = "changed"

	unchanged, err := repository.Get(original.ID)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.Targets[0].Name != "host" || unchanged.Ports[0] != 80 ||
		unchanged.Findings[0].ID != "finding" || unchanged.Observations[0].Metadata["server"] != "nginx" {
		t.Fatalf("stored scan was mutated through a returned value: %#v", unchanged)
	}
}

func TestSQLiteStoreImportsAndArchivesLegacyJSON(t *testing.T) {
	directory := t.TempDir()
	legacyPath := filepath.Join(directory, "scans.json")
	legacy := `{"legacy":{"id":"legacy","name":"old scan","status":"completed","findings":[{"id":"open","target":"host","address":"127.0.0.1","port":80,"service":"http","severity":"info","evidence":"reachable","observed_at":"2026-01-01T00:00:00Z"}],"created_at":"2026-01-01T00:00:00Z"}}`
	if err := os.WriteFile(legacyPath, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	repository, err := NewSQLiteStore(filepath.Join(directory, "mossward.db"), legacyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	scan, err := repository.Get("legacy")
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.Findings) != 0 || len(scan.Observations) != 1 || scan.Observations[0].Protocol != "http" {
		t.Fatalf("legacy scan was not normalized during import: %#v", scan)
	}
	if _, err := os.Stat(legacyPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected original JSON file to be archived, got %v", err)
	}
	if _, err := os.Stat(legacyPath + ".imported"); err != nil {
		t.Fatalf("expected recoverable imported archive: %v", err)
	}
}

func TestSQLiteStoreListsNewestFirst(t *testing.T) {
	repository := openTestStore(t)
	for _, scan := range []model.Scan{
		{ID: "older", Status: model.StatusCompleted, CreatedAt: time.Now().UTC().Add(-time.Hour)},
		{ID: "newer", Status: model.StatusCompleted, CreatedAt: time.Now().UTC()},
	} {
		if err := repository.Save(scan); err != nil {
			t.Fatal(err)
		}
	}
	scans, err := repository.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(scans) != 2 || scans[0].ID != "newer" {
		t.Fatalf("unexpected scan ordering: %#v", scans)
	}
}

func TestSQLiteStoreReturnsNotFound(t *testing.T) {
	repository := openTestStore(t)
	_, err := repository.Get("missing")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestSQLiteStoreMatchesVersionedObservationAndPrioritizesNews(t *testing.T) {
	repository := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	record := model.CVERecord{ID: "CVE-2026-4242", Description: "Critical nginx issue", PublishedAt: now,
		ModifiedAt: now, CVSSScore: 9.8, Severity: "critical", KnownExploited: true,
		SourceURL: "https://nvd.nist.gov/vuln/detail/CVE-2026-4242", Products: []model.AffectedProduct{{
			CPE23: "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*", Vendor: "nginx", Product: "nginx",
			VersionEndExcluding: "1.25.4", Vulnerable: true,
		}}}
	if err := repository.UpsertCVEs([]model.CVERecord{record}); err != nil {
		t.Fatal(err)
	}
	observation := model.ServiceObservation{ID: "obs", Target: "web", Address: "127.0.0.1", Port: 443,
		Product: "nginx", Version: "1.25.3", ObservedAt: now}
	matches, err := repository.MatchObservation(observation)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || matches[0].CVEID != record.ID {
		t.Fatalf("unexpected matches: %#v", matches)
	}
	scan := model.Scan{ID: "matched-scan", Status: model.StatusCompleted, CreatedAt: now,
		Observations: []model.ServiceObservation{observation}, CVEMatches: matches}
	if err := repository.Save(scan); err != nil {
		t.Fatal(err)
	}
	loaded, err := repository.Get(scan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.CVEMatches) != 1 || loaded.CVEMatches[0].KnownExploited != true {
		t.Fatalf("CVE match did not round-trip: %#v", loaded.CVEMatches)
	}
	news, err := repository.ListCriticalNews(6)
	if err != nil {
		t.Fatal(err)
	}
	if len(news) != 1 || news[0].Relevance != "matched" {
		t.Fatalf("unexpected news relevance: %#v", news)
	}
}

func TestSQLiteStoreDoesNotMatchWithoutVersion(t *testing.T) {
	repository := openTestStore(t)
	matches, err := repository.MatchObservation(model.ServiceObservation{Product: "nginx"})
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("expected no unversioned matches, got %#v", matches)
	}
}

func TestIdentitySchemaMigrationCreatesSecurityTables(t *testing.T) {
	repository := openTestStore(t)
	for _, table := range []string{
		"users", "invitations", "sessions", "login_attempts", "totp_credentials",
		"recovery_codes", "webauthn_credentials", "authentication_ceremonies",
		"oidc_providers", "external_identities", "audit_events", "scope_policies",
		"agent_enrollment_tokens", "endpoints",
	} {
		var found string
		err := repository.db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&found)
		if err != nil {
			t.Errorf("identity table %q was not created: %v", table, err)
		}
	}
	var version int
	if err := repository.db.QueryRow(`SELECT MAX(version) FROM schema_migrations`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != schemaVersion {
		t.Fatalf("schema version = %d, want %d", version, schemaVersion)
	}
}

func TestScopePolicyRoundTrip(t *testing.T) {
	repository := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	policy := model.ScopePolicy{ID: "policy", Name: "Restricted", AllowedCIDRs: []string{"10.0.0.0/8"},
		AllowedPorts: []int{22, 443}, MaxTargets: 25, MaxConcurrent: 4, Enabled: true, CreatedAt: now, UpdatedAt: now}
	event := model.AuditEvent{OccurredAt: now, Action: "scope.test", Severity: model.AuditInfo}
	if err := repository.UpsertScopePolicy(policy, event); err != nil {
		t.Fatal(err)
	}
	loaded, err := repository.ScopePolicy(policy.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Name != policy.Name || len(loaded.AllowedCIDRs) != 1 || len(loaded.AllowedPorts) != 2 ||
		loaded.MaxTargets != 25 || loaded.MaxConcurrent != 4 || !loaded.Enabled {
		t.Fatalf("scope policy did not round-trip: %#v", loaded)
	}
}
