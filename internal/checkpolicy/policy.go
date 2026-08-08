package checkpolicy

import (
	"errors"
	"strings"
	"time"

	"mossward/internal/checkdefinition"
)

var (
	ErrIntrusiveDisabled = errors.New("intrusive declarative checks are disabled")
	ErrCheckNotAllowed   = errors.New("intrusive declarative check is not allowlisted")
	ErrApprovalRequired  = errors.New("a current intrusive-check approval is required")
)

type Policy struct {
	Enabled         bool
	AllowedCheckIDs []string
	UpdatedAt       time.Time
}

type Approval struct {
	CheckID    string
	Version    string
	ApprovedBy string
	ApprovedAt time.Time
	ExpiresAt  time.Time
}

func Validate(policy Policy) error {
	if policy.UpdatedAt.IsZero() {
		return errors.New("intrusive-check policy update time is required")
	}
	seen := make(map[string]bool)
	for _, id := range policy.AllowedCheckIDs {
		if strings.TrimSpace(id) != id || !strings.Contains(id, ".") || seen[id] {
			return errors.New("intrusive-check policy contains an invalid or duplicate check identifier")
		}
		seen[id] = true
	}
	return nil
}

func Authorize(check checkdefinition.Check, policy Policy, approval *Approval, now time.Time) error {
	if !checkdefinition.IsIntrusive(check) {
		return nil
	}
	if !policy.Enabled {
		return ErrIntrusiveDisabled
	}
	if !contains(policy.AllowedCheckIDs, check.ID) {
		return ErrCheckNotAllowed
	}
	if approval == nil || approval.CheckID != check.ID || approval.Version != check.Version ||
		strings.TrimSpace(approval.ApprovedBy) == "" || approval.ApprovedAt.After(now) || !approval.ExpiresAt.After(now) {
		return ErrApprovalRequired
	}
	return nil
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
