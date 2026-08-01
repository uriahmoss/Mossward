package scanner

import (
	"path/filepath"
	"testing"
	"time"

	"mossward/internal/config"
	"mossward/internal/model"
	"mossward/internal/store"
)

func testEngine(t *testing.T) *Engine {
	t.Helper()
	repository, err := store.NewSQLiteStore(filepath.Join(t.TempDir(), "mossward.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repository.Close() })
	engine, err := New(config.Config{
		AllowedCIDRs:   []string{"127.0.0.0/8", "::1/128"},
		AllowedPorts:   map[int]bool{80: true, 443: true},
		MaxTargets:     10,
		MaxConcurrent:  2,
		QueueSize:      2,
		ConnectTimeout: 50 * time.Millisecond,
	}, repository)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Shutdown)
	return engine
}

func TestValidateAllowsLoopback(t *testing.T) {
	engine := testEngine(t)
	targets, ports, err := engine.Validate(model.CreateScanRequest{Targets: []string{"127.0.0.1"}, Ports: []int{443}})
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || len(ports) != 1 {
		t.Fatalf("unexpected targets or ports: %v %v", targets, ports)
	}
	if targets[0].Address != "127.0.0.1" {
		t.Fatalf("expected pinned loopback address, got %q", targets[0].Address)
	}
}

func TestValidateRejectsPublicAddress(t *testing.T) {
	engine := testEngine(t)
	_, _, err := engine.Validate(model.CreateScanRequest{Targets: []string{"8.8.8.8"}, Ports: []int{443}})
	if err == nil {
		t.Fatal("expected public address to be rejected")
	}
}

func TestValidateRejectsUnlistedPort(t *testing.T) {
	engine := testEngine(t)
	_, _, err := engine.Validate(model.CreateScanRequest{Targets: []string{"127.0.0.1"}, Ports: []int{4444}})
	if err == nil {
		t.Fatal("expected unlisted port to be rejected")
	}
}

func TestValidateDeduplicatesPorts(t *testing.T) {
	engine := testEngine(t)
	_, ports, err := engine.Validate(model.CreateScanRequest{
		Targets: []string{"127.0.0.1"},
		Ports:   []int{443, 80, 443},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(ports) != 2 || ports[0] != 80 || ports[1] != 443 {
		t.Fatalf("expected sorted unique ports, got %v", ports)
	}
}

func TestScheduledInterruptionPausesForResume(t *testing.T) {
	engine := testEngine(t)
	started := time.Now().UTC().Add(-time.Minute)
	scan := model.Scan{ID: "scheduled-interruption", Name: "Nightly", Status: model.StatusRunning,
		CreatedAt: started, StartedAt: &started, ScanPolicyID: "policy", Targets: []model.Target{}, Ports: []int{443}}
	engine.interrupt(scan, "server shutdown")
	stored, err := engine.store.Get(scan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != model.StatusPaused || stored.CompletedAt != nil || stored.ActiveSeconds < 59 {
		t.Fatalf("scheduled scan was not resumably paused: %#v", stored)
	}
}

func TestValidateExpandsIPv4CIDRWithoutNetworkAndBroadcast(t *testing.T) {
	engine := testEngine(t)
	targets, _, err := engine.Validate(model.CreateScanRequest{
		Targets: []string{"127.0.0.0/30"},
		Ports:   []int{80},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 2 || targets[0].Address != "127.0.0.1" || targets[1].Address != "127.0.0.2" {
		t.Fatalf("unexpected CIDR expansion: %#v", targets)
	}
}

func TestValidateExpandsInclusiveAddressRange(t *testing.T) {
	engine := testEngine(t)
	targets, _, err := engine.Validate(model.CreateScanRequest{
		Targets: []string{"127.0.0.3-127.0.0.5"},
		Ports:   []int{80},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 3 || targets[0].Address != "127.0.0.3" || targets[2].Address != "127.0.0.5" {
		t.Fatalf("unexpected range expansion: %#v", targets)
	}
}

func TestValidateRejectsRangeOutsideAllowlist(t *testing.T) {
	engine := testEngine(t)
	_, _, err := engine.Validate(model.CreateScanRequest{
		Targets: []string{"127.0.0.1-8.8.8.8"},
		Ports:   []int{80},
	})
	if err == nil {
		t.Fatal("expected mixed-scope range to be rejected")
	}
}

func TestValidateRejectsExpansionBeyondLimit(t *testing.T) {
	engine := testEngine(t)
	_, _, err := engine.Validate(model.CreateScanRequest{
		Targets: []string{"127.0.0.0/24"},
		Ports:   []int{80},
	})
	if err == nil {
		t.Fatal("expected oversized CIDR to be rejected")
	}
}

func TestValidateDeduplicatesOverlappingTargets(t *testing.T) {
	engine := testEngine(t)
	targets, _, err := engine.Validate(model.CreateScanRequest{
		Targets: []string{"127.0.0.1", "127.0.0.1-127.0.0.2"},
		Ports:   []int{80},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 2 {
		t.Fatalf("expected two unique addresses, got %#v", targets)
	}
}

func TestValidateWithScopePolicyUsesDatabasePolicyLimits(t *testing.T) {
	engine := testEngine(t)
	policy := model.ScopePolicy{ID: "restricted", Name: "Restricted", Enabled: true,
		AllowedCIDRs: []string{"127.0.0.0/30"}, AllowedPorts: []int{443}, MaxTargets: 1, MaxConcurrent: 1}
	if _, _, err := engine.ValidateWithPolicy(model.CreateScanRequest{Targets: []string{"127.0.0.1"}, Ports: []int{443}}, policy); err != nil {
		t.Fatal(err)
	}
	for _, request := range []model.CreateScanRequest{
		{Targets: []string{"127.0.0.1"}, Ports: []int{80}},
		{Targets: []string{"127.0.0.1-127.0.0.2"}, Ports: []int{443}},
		{Targets: []string{"127.0.0.4"}, Ports: []int{443}},
	} {
		if _, _, err := engine.ValidateWithPolicy(request, policy); err == nil {
			t.Fatalf("expected policy rejection for %#v", request)
		}
	}
}

func TestScopePolicyCannotExceedServerSafetyCaps(t *testing.T) {
	engine := testEngine(t)
	policy := model.ScopePolicy{Name: "Too broad", Enabled: true, AllowedCIDRs: []string{"0.0.0.0/0"},
		AllowedPorts: []int{443}, MaxTargets: 11, MaxConcurrent: 3}
	if err := engine.ValidatePolicy(policy); err == nil {
		t.Fatal("expected server safety caps to reject policy")
	}
}
