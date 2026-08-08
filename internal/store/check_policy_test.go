package store

import (
	"testing"
	"time"

	"mossward/internal/checkpolicy"
)

func TestIntrusiveCheckPolicyDefaultsDisabledAndPersists(t *testing.T) {
	repository := openTestStore(t)
	policy, err := repository.IntrusiveCheckPolicy()
	if err != nil || policy.Enabled || len(policy.AllowedCheckIDs) != 0 {
		t.Fatalf("unexpected default policy: %#v, %v", policy, err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	expected := checkpolicy.Policy{Enabled: true, AllowedCheckIDs: []string{"vendor.intrusive.example"}, UpdatedAt: now}
	if err := repository.SaveIntrusiveCheckPolicy(expected); err != nil {
		t.Fatal(err)
	}
	loaded, err := repository.IntrusiveCheckPolicy()
	if err != nil || !loaded.Enabled || len(loaded.AllowedCheckIDs) != 1 || loaded.AllowedCheckIDs[0] != expected.AllowedCheckIDs[0] {
		t.Fatalf("unexpected saved policy: %#v, %v", loaded, err)
	}
}
