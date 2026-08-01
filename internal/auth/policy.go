package auth

import (
	"errors"
	"strings"

	"mossward/internal/model"
)

const (
	minimumSessionMinutes = 15
	maximumSessionMinutes = 7 * 24 * 60
	minimumRetentionDays  = 1
	maximumRetentionDays  = 3650
	maximumAuditResults   = 500
)

func (s *Service) Policy() (model.AuthenticationPolicy, error) {
	return s.store.AuthenticationPolicy()
}

func (s *Service) UpdatePolicy(actor model.User, policy model.AuthenticationPolicy, sourceIP string) error {
	if err := validateAuthenticationPolicy(policy); err != nil {
		return err
	}
	now := s.now()
	event := model.AuditEvent{OccurredAt: now, ActorID: actor.ID, Action: "identity.authentication_policy.updated",
		Severity: model.AuditWarning, TargetType: "authentication_policy", SourceIP: sourceIP,
		Details: jsonObject(map[string]any{"session_lifetime_minutes": policy.SessionLifetimeMinutes,
			"audit_retention_days": policy.AuditRetentionDays, "mfa_required": policy.MFARequired})}
	return s.store.SaveAuthenticationPolicy(policy, now, event)
}

func (s *Service) AuditEvents(text string, severity model.AuditSeverity, limit int) ([]model.AuditEvent, error) {
	if limit <= 0 || limit > maximumAuditResults {
		limit = maximumAuditResults
	}
	if severity != "" && severity != model.AuditInfo && severity != model.AuditWarning && severity != model.AuditError {
		return nil, errors.New("invalid audit severity")
	}
	return s.store.ListAuditEvents(model.AuditQuery{Text: strings.TrimSpace(text), Severity: severity, Limit: limit})
}

func validateAuthenticationPolicy(policy model.AuthenticationPolicy) error {
	if policy.SessionLifetimeMinutes < minimumSessionMinutes || policy.SessionLifetimeMinutes > maximumSessionMinutes {
		return errors.New("session lifetime must be between 15 minutes and 7 days")
	}
	if policy.AuditRetentionDays < minimumRetentionDays || policy.AuditRetentionDays > maximumRetentionDays {
		return errors.New("audit retention must be between 1 and 3650 days")
	}
	if !policy.MFARequired[model.RoleAdministrator] {
		return errors.New("administrator MFA cannot be disabled")
	}
	return nil
}
