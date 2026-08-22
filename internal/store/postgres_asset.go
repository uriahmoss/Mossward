package store

import (
	"database/sql"
	"fmt"
	"time"

	"mossward/internal/model"
)

func (s *PostgreSQLStore) ListAssets() ([]model.Asset, error) {
	settings, err := s.AssetAgingSettings()
	if err != nil {
		return nil, fmt.Errorf("load PostgreSQL asset aging settings: %w", err)
	}
	rows, err := s.db.Query(`SELECT id,name,address,first_seen,last_seen,last_scan_id,owner,environment,classification,
		lifecycle_status,retired_at,retired_by,retirement_reason,agent_eligibility,agent_eligibility_reason,
		agent_eligibility_updated_by,agent_eligibility_updated_at FROM assets ORDER BY lifecycle_status,last_seen DESC,name`)
	if err != nil {
		return nil, fmt.Errorf("list PostgreSQL assets: %w", err)
	}
	assets := []model.Asset{}
	for rows.Next() {
		var asset model.Asset
		var retiredAt, eligibilityUpdatedAt sql.NullTime
		if err := rows.Scan(&asset.ID, &asset.Name, &asset.Address, &asset.FirstSeen, &asset.LastSeen, &asset.LastScanID,
			&asset.Owner, &asset.Environment, &asset.Classification, &asset.Lifecycle.Status, &retiredAt,
			&asset.Lifecycle.RetiredBy, &asset.Lifecycle.RetirementReason, &asset.AgentEligibility.Status,
			&asset.AgentEligibility.Reason, &asset.AgentEligibility.UpdatedBy, &eligibilityUpdatedAt); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("read PostgreSQL asset: %w", err)
		}
		asset.Lifecycle.RetiredAt = nullablePostgreSQLTime(retiredAt)
		asset.AgentEligibility.UpdatedAt = nullablePostgreSQLTime(eligibilityUpdatedAt)
		if asset.Lifecycle.Status == model.AssetActive && time.Since(asset.LastSeen) >= time.Duration(settings.StaleAfterDays)*24*time.Hour {
			asset.Lifecycle.Status = model.AssetStale
		}
		assets = append(assets, asset)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close PostgreSQL assets: %w", err)
	}
	for index := range assets {
		if err := s.loadPostgreSQLAssetIdentity(&assets[index]); err != nil {
			return nil, err
		}
	}
	return assets, nil
}

func (s *PostgreSQLStore) loadPostgreSQLAssetIdentity(asset *model.Asset) error {
	nameRows, err := s.db.Query(`SELECT name FROM asset_names WHERE asset_id=$1 ORDER BY name`, asset.ID)
	if err != nil {
		return fmt.Errorf("load PostgreSQL asset names: %w", err)
	}
	asset.Names = []string{}
	for nameRows.Next() {
		var name string
		if err := nameRows.Scan(&name); err != nil {
			_ = nameRows.Close()
			return fmt.Errorf("read PostgreSQL asset name: %w", err)
		}
		asset.Names = append(asset.Names, name)
	}
	if err := nameRows.Close(); err != nil {
		return err
	}
	addressRows, err := s.db.Query(`SELECT address,first_seen,last_seen,last_scan_id FROM asset_addresses WHERE asset_id=$1 ORDER BY address`, asset.ID)
	if err != nil {
		return fmt.Errorf("load PostgreSQL asset addresses: %w", err)
	}
	defer addressRows.Close()
	asset.Addresses = []model.AssetAddress{}
	for addressRows.Next() {
		var address model.AssetAddress
		if err := addressRows.Scan(&address.Address, &address.FirstSeen, &address.LastSeen, &address.LastScanID); err != nil {
			return fmt.Errorf("read PostgreSQL asset address: %w", err)
		}
		asset.Addresses = append(asset.Addresses, address)
	}
	return addressRows.Err()
}

func (s *PostgreSQLStore) UpdateAssetMetadata(id string, metadata model.AssetMetadata, event model.AuditEvent) error {
	return s.updatePostgreSQLAsset(`UPDATE assets SET owner=$1,environment=$2,classification=$3 WHERE id=$4`,
		[]any{metadata.Owner, metadata.Environment, metadata.Classification, id}, event, "metadata")
}

func (s *PostgreSQLStore) UpdateAssetAgentEligibility(id string, update model.AssetAgentEligibilityUpdate, event model.AuditEvent) error {
	return s.updatePostgreSQLAsset(`UPDATE assets SET agent_eligibility=$1,agent_eligibility_reason=$2,
		agent_eligibility_updated_by=$3,agent_eligibility_updated_at=$4 WHERE id=$5`,
		[]any{update.Status, update.Reason, event.ActorID, event.OccurredAt, id}, event, "agent eligibility")
}

func (s *PostgreSQLStore) UpdateAssetLifecycle(id string, update model.AssetLifecycleUpdate, event model.AuditEvent) error {
	if update.Status != model.AssetActive && update.Status != model.AssetRetired {
		return ErrInvalidAssetLifecycle
	}
	if update.Status == model.AssetRetired {
		return s.updatePostgreSQLAsset(`UPDATE assets SET lifecycle_status=$1,retired_at=$2,retired_by=$3,retirement_reason=$4 WHERE id=$5`,
			[]any{update.Status, event.OccurredAt, event.ActorID, update.Reason, id}, event, "lifecycle")
	}
	return s.updatePostgreSQLAsset(`UPDATE assets SET lifecycle_status=$1,retired_at=NULL,retired_by='',retirement_reason='' WHERE id=$2`,
		[]any{update.Status, id}, event, "lifecycle")
}

func (s *PostgreSQLStore) updatePostgreSQLAsset(query string, arguments []any, event model.AuditEvent, operation string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL asset %s update: %w", operation, err)
	}
	defer tx.Rollback()
	result, err := tx.Exec(query, arguments...)
	if err != nil {
		return fmt.Errorf("update PostgreSQL asset %s: %w", operation, err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read PostgreSQL asset %s result: %w", operation, err)
	}
	if changed != 1 {
		return ErrAssetNotFound
	}
	if err := insertPostgreSQLAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgreSQLStore) AssetAgingSettings() (model.AssetAgingSettings, error) {
	var settings model.AssetAgingSettings
	err := s.db.QueryRow(`SELECT stale_after_days FROM asset_aging_settings WHERE singleton=1`).Scan(&settings.StaleAfterDays)
	if err != nil {
		return settings, fmt.Errorf("load PostgreSQL asset aging settings: %w", err)
	}
	return settings, nil
}

func (s *PostgreSQLStore) UpdateAssetAgingSettings(settings model.AssetAgingSettings, event model.AuditEvent) error {
	if settings.StaleAfterDays < minimumAssetStaleDays || settings.StaleAfterDays > maximumAssetStaleDays {
		return fmt.Errorf("asset stale threshold must be between %d and %d days", minimumAssetStaleDays, maximumAssetStaleDays)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL asset aging update: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE asset_aging_settings SET stale_after_days=$1 WHERE singleton=1`, settings.StaleAfterDays); err != nil {
		return fmt.Errorf("update PostgreSQL asset aging settings: %w", err)
	}
	if err := insertPostgreSQLAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}
