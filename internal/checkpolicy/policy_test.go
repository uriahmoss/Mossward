package checkpolicy

import (
	"errors"
	"testing"
	"time"

	"mossward/internal/checkdefinition"
)

func TestIntrusiveChecksRequireBothPolicyAndExactApproval(t *testing.T) {
	now := time.Now().UTC()
	check := checkdefinition.Check{ID: "vendor.intrusive.example", Version: "1.2.0", ExecutionClass: checkdefinition.ExecutionIntrusive}
	if err := Authorize(check, Policy{}, nil, now); !errors.Is(err, ErrIntrusiveDisabled) {
		t.Fatalf("disabled error = %v", err)
	}
	policy := Policy{Enabled: true, AllowedCheckIDs: []string{"other.check"}}
	if err := Authorize(check, policy, nil, now); !errors.Is(err, ErrCheckNotAllowed) {
		t.Fatalf("allowlist error = %v", err)
	}
	policy.AllowedCheckIDs = []string{check.ID}
	approval := &Approval{CheckID: check.ID, Version: "1.1.0", ApprovedBy: "admin", ApprovedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := Authorize(check, policy, approval, now); !errors.Is(err, ErrApprovalRequired) {
		t.Fatalf("version error = %v", err)
	}
	approval.Version = check.Version
	if err := Authorize(check, policy, approval, now); err != nil {
		t.Fatalf("authorize intrusive check: %v", err)
	}
}

func TestObservationalChecksDoNotUseIntrusivePolicy(t *testing.T) {
	check := checkdefinition.Check{ID: "mossward.http.safe", Version: "1.0.0", ExecutionClass: checkdefinition.ExecutionObservational}
	if err := Authorize(check, Policy{}, nil, time.Now()); err != nil {
		t.Fatalf("observational check denied: %v", err)
	}
}
