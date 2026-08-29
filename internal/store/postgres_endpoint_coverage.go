package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"mossward/internal/model"
)

func (s *PostgreSQLStore) EndpointCoverageSettings() (model.EndpointCoverageSettings, error) {
	var settings model.EndpointCoverageSettings
	var updatedAt sql.NullTime
	err := s.db.QueryRow(`SELECT enabled,updated_by,updated_at FROM endpoint_coverage_settings
		WHERE singleton=TRUE`).Scan(&settings.Enabled, &settings.UpdatedBy, &updatedAt)
	if err != nil {
		return settings, fmt.Errorf("read PostgreSQL endpoint coverage settings: %w", err)
	}
	if updatedAt.Valid {
		settings.UpdatedAt = updatedAt.Time
	}
	return settings, nil
}

func (s *PostgreSQLStore) SetEndpointCoverageSettings(settings model.EndpointCoverageSettings, event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL endpoint coverage-settings update: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.Exec(`UPDATE endpoint_coverage_settings SET enabled=$1,updated_by=$2,updated_at=$3
		WHERE singleton=TRUE`, settings.Enabled, settings.UpdatedBy, settings.UpdatedAt)
	if err != nil {
		return fmt.Errorf("update PostgreSQL endpoint coverage settings: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return ErrNotFound
	}
	if err := insertPostgreSQLAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgreSQLStore) EndpointCoverageReport(now time.Time) (model.EndpointCoverageReport, error) {
	settings, err := s.EndpointCoverageSettings()
	report := model.EndpointCoverageReport{
		Enabled: settings.Enabled, EvaluatedAt: now, Gaps: []model.EndpointCoverageGap{}, Unclassified: []model.EndpointCoverageGap{},
	}
	if err != nil || !settings.Enabled {
		return report, err
	}
	rows, err := s.db.Query(`SELECT a.id,a.name,a.address,a.last_seen,a.agent_eligibility,a.agent_eligibility_reason
		FROM assets a WHERE a.lifecycle_status<>'retired' AND NOT EXISTS(
		SELECT 1 FROM endpoints e WHERE e.asset_id=a.id AND e.status='active')
		AND a.agent_eligibility<>'ineligible' ORDER BY a.last_seen DESC,a.name,a.id`)
	if err != nil {
		return report, fmt.Errorf("query PostgreSQL endpoint coverage gaps: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var gap model.EndpointCoverageGap
		if err := rows.Scan(&gap.AssetID, &gap.Name, &gap.Address, &gap.LastSeen, &gap.Eligibility,
			&gap.EligibilityReason); err != nil {
			return report, fmt.Errorf("read PostgreSQL endpoint coverage gap: %w", err)
		}
		gap.Reason = missingEndpointReason
		if gap.Eligibility == model.AgentEligibilityEligible {
			report.Gaps = append(report.Gaps, gap)
			continue
		}
		gap.Reason = "agent eligibility has not been classified"
		report.Unclassified = append(report.Unclassified, gap)
	}
	return report, rows.Err()
}

func (s *PostgreSQLStore) SaveCoverageDiscoveryPolicy(policy model.CoverageDiscoveryPolicy, event model.AuditEvent) error {
	cidrs, err := json.Marshal(policy.CIDRs)
	if err != nil {
		return fmt.Errorf("encode PostgreSQL coverage discovery CIDRs: %w", err)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL coverage discovery-policy update: %w", err)
	}
	defer tx.Rollback()
	var existingCreatedBy string
	var existingCreatedAt time.Time
	lookupErr := tx.QueryRow(`SELECT created_by,created_at FROM coverage_discovery_policies
		WHERE id=$1 FOR UPDATE`, policy.ID).Scan(&existingCreatedBy, &existingCreatedAt)
	switch {
	case errors.Is(lookupErr, sql.ErrNoRows) && policy.CreatedBy == "":
		return ErrNotFound
	case errors.Is(lookupErr, sql.ErrNoRows):
		_, err = tx.Exec(`INSERT INTO coverage_discovery_policies
			(id,name,cidrs,enabled,created_by,created_at,updated_by,updated_at)
			VALUES($1,$2,$3::jsonb,$4,$5,$6,$7,$8)`, policy.ID, policy.Name, string(cidrs), policy.Enabled,
			policy.CreatedBy, policy.CreatedAt, policy.UpdatedBy, policy.UpdatedAt)
	case lookupErr != nil:
		return fmt.Errorf("read PostgreSQL coverage discovery policy: %w", lookupErr)
	default:
		_, err = tx.Exec(`UPDATE coverage_discovery_policies SET name=$1,cidrs=$2::jsonb,enabled=$3,
			updated_by=$4,updated_at=$5 WHERE id=$6`, policy.Name, string(cidrs), policy.Enabled,
			policy.UpdatedBy, policy.UpdatedAt, policy.ID)
	}
	if err != nil {
		return fmt.Errorf("save PostgreSQL coverage discovery policy: %w", err)
	}
	if err := insertPostgreSQLAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgreSQLStore) ListCoverageDiscoveryPolicies() ([]model.CoverageDiscoveryPolicy, error) {
	rows, err := s.db.Query(`SELECT id,name,cidrs,enabled,created_by,created_at,updated_by,updated_at
		FROM coverage_discovery_policies ORDER BY name,id`)
	if err != nil {
		return nil, fmt.Errorf("list PostgreSQL coverage discovery policies: %w", err)
	}
	defer rows.Close()
	policies := []model.CoverageDiscoveryPolicy{}
	for rows.Next() {
		var policy model.CoverageDiscoveryPolicy
		var cidrs []byte
		if err := rows.Scan(&policy.ID, &policy.Name, &cidrs, &policy.Enabled, &policy.CreatedBy, &policy.CreatedAt,
			&policy.UpdatedBy, &policy.UpdatedAt); err != nil {
			return nil, fmt.Errorf("read PostgreSQL coverage discovery policy: %w", err)
		}
		if err := json.Unmarshal(cidrs, &policy.CIDRs); err != nil {
			return nil, fmt.Errorf("decode PostgreSQL coverage discovery CIDRs: %w", err)
		}
		policies = append(policies, policy)
	}
	return policies, rows.Err()
}
