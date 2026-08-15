package store

import (
	"time"

	"mossward/internal/model"
)

const missingEndpointReason = "no active endpoint is linked to this asset"

func (s *SQLiteStore) EndpointCoverageSettings() (model.EndpointCoverageSettings, error) {
	var settings model.EndpointCoverageSettings
	var updatedAt string
	err := s.db.QueryRow(`SELECT enabled,updated_by,updated_at FROM endpoint_coverage_settings WHERE singleton=1`).
		Scan(&settings.Enabled, &settings.UpdatedBy, &updatedAt)
	if err != nil {
		return settings, err
	}
	if updatedAt != "" {
		settings.UpdatedAt, _ = parseTime(updatedAt)
	}
	return settings, nil
}

func (s *SQLiteStore) SetEndpointCoverageSettings(settings model.EndpointCoverageSettings, event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.Exec(`UPDATE endpoint_coverage_settings SET enabled=?,updated_by=?,updated_at=? WHERE singleton=1`,
		settings.Enabled, settings.UpdatedBy, formatTime(settings.UpdatedAt))
	if err != nil {
		return err
	}
	if err := insertAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLiteStore) EndpointCoverageReport(now time.Time) (model.EndpointCoverageReport, error) {
	settings, err := s.EndpointCoverageSettings()
	report := model.EndpointCoverageReport{Enabled: settings.Enabled, EvaluatedAt: now, Gaps: []model.EndpointCoverageGap{}, Unclassified: []model.EndpointCoverageGap{}}
	if err != nil || !settings.Enabled {
		return report, err
	}
	rows, err := s.db.Query(`SELECT a.id,a.name,a.address,a.last_seen,a.agent_eligibility,a.agent_eligibility_reason FROM assets a
		WHERE a.lifecycle_status<>'retired' AND NOT EXISTS (
			SELECT 1 FROM endpoints e WHERE e.asset_id=a.id AND e.status='active')
			AND a.agent_eligibility<>'ineligible'
		ORDER BY a.last_seen DESC,a.name,a.id`)
	if err != nil {
		return report, err
	}
	defer rows.Close()
	for rows.Next() {
		var gap model.EndpointCoverageGap
		var lastSeen string
		if err := rows.Scan(&gap.AssetID, &gap.Name, &gap.Address, &lastSeen, &gap.Eligibility, &gap.EligibilityReason); err != nil {
			return report, err
		}
		gap.LastSeen, _ = parseTime(lastSeen)
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
