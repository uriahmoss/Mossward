package store

import (
	"database/sql"
	"errors"
	"fmt"

	"mossward/internal/model"
)

type mergeAssetRecord struct {
	ID               string
	Name             string
	Address          string
	FirstSeen        string
	LastSeen         string
	LastScanID       string
	Owner            string
	Environment      string
	Classification   string
	LifecycleStatus  string
	RetiredAt        sql.NullString
	RetiredBy        string
	RetirementReason string
}

type mergeServiceRecord struct {
	Address          string
	Port             int
	Protocol         string
	Product          string
	Version          string
	Confidence       string
	State            string
	FirstSeen        string
	LastSeen         string
	LastChecked      string
	LastScanID       string
	ObservationCount int
}

func (s *SQLiteStore) MergeAssets(request model.AssetMergeRequest, event model.AuditEvent) error {
	if request.SurvivorID == "" || request.MergedID == "" || request.SurvivorID == request.MergedID {
		return errors.New("two different assets are required")
	}
	if !validMergeSources(request) {
		return errors.New("each selected value must come from one of the merged assets")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin asset merge: %w", err)
	}
	defer tx.Rollback()
	survivor, err := loadMergeAsset(tx, request.SurvivorID)
	if err != nil {
		return err
	}
	merged, err := loadMergeAsset(tx, request.MergedID)
	if err != nil {
		return err
	}
	selected := mergeSelectedAsset(request, survivor, merged)
	if err := transferAssetRelationships(tx, request.SurvivorID, request.MergedID); err != nil {
		return err
	}
	if err := mergeAssetServices(tx, request.SurvivorID, request.MergedID); err != nil {
		return err
	}
	firstSeen, lastSeen, lastScanID := mergedAssetTimes(survivor, merged)
	if _, err := tx.Exec(`DELETE FROM assets WHERE id=?`, request.MergedID); err != nil {
		return fmt.Errorf("remove merged asset: %w", err)
	}
	_, err = tx.Exec(`UPDATE assets SET name=?,address=?,first_seen=?,last_seen=?,last_scan_id=?,owner=?,environment=?,classification=?,lifecycle_status=?,retired_at=?,retired_by=?,retirement_reason=? WHERE id=?`,
		selected.Name, selected.Address, firstSeen, lastSeen, lastScanID, selected.Owner, selected.Environment,
		selected.Classification, selected.LifecycleStatus, selected.RetiredAt, selected.RetiredBy,
		selected.RetirementReason, request.SurvivorID)
	if err != nil {
		return fmt.Errorf("update merged asset: %w", err)
	}
	if err := insertAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func validMergeSources(request model.AssetMergeRequest) bool {
	valid := func(id string) bool { return id == request.SurvivorID || id == request.MergedID }
	return valid(request.NameFrom) && valid(request.AddressFrom) && valid(request.OwnerFrom) &&
		valid(request.EnvironmentFrom) && valid(request.ClassificationFrom) && valid(request.LifecycleFrom)
}

func loadMergeAsset(tx *sql.Tx, id string) (mergeAssetRecord, error) {
	var asset mergeAssetRecord
	err := tx.QueryRow(`SELECT id,name,address,first_seen,last_seen,last_scan_id,owner,environment,classification,lifecycle_status,retired_at,retired_by,retirement_reason FROM assets WHERE id=?`, id).Scan(
		&asset.ID, &asset.Name, &asset.Address, &asset.FirstSeen, &asset.LastSeen, &asset.LastScanID,
		&asset.Owner, &asset.Environment, &asset.Classification, &asset.LifecycleStatus, &asset.RetiredAt,
		&asset.RetiredBy, &asset.RetirementReason)
	if errors.Is(err, sql.ErrNoRows) {
		return asset, ErrAssetNotFound
	}
	return asset, err
}

func mergeSelectedAsset(request model.AssetMergeRequest, survivor, merged mergeAssetRecord) mergeAssetRecord {
	byID := map[string]mergeAssetRecord{survivor.ID: survivor, merged.ID: merged}
	return mergeAssetRecord{
		Name:             byID[request.NameFrom].Name,
		Address:          byID[request.AddressFrom].Address,
		Owner:            byID[request.OwnerFrom].Owner,
		Environment:      byID[request.EnvironmentFrom].Environment,
		Classification:   byID[request.ClassificationFrom].Classification,
		LifecycleStatus:  byID[request.LifecycleFrom].LifecycleStatus,
		RetiredAt:        byID[request.LifecycleFrom].RetiredAt,
		RetiredBy:        byID[request.LifecycleFrom].RetiredBy,
		RetirementReason: byID[request.LifecycleFrom].RetirementReason,
	}
}

func mergedAssetTimes(survivor, merged mergeAssetRecord) (string, string, string) {
	firstSeen := survivor.FirstSeen
	if merged.FirstSeen < firstSeen {
		firstSeen = merged.FirstSeen
	}
	lastSeen := survivor.LastSeen
	lastScanID := survivor.LastScanID
	if merged.LastSeen > lastSeen {
		lastSeen = merged.LastSeen
		lastScanID = merged.LastScanID
	}
	return firstSeen, lastSeen, lastScanID
}

func transferAssetRelationships(tx *sql.Tx, survivorID, mergedID string) error {
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO asset_group_members(group_id,asset_id,added_at,added_by) SELECT group_id,?,added_at,added_by FROM asset_group_members WHERE asset_id=? ON CONFLICT(group_id,asset_id) DO NOTHING`, []any{survivorID, mergedID}},
		{`DELETE FROM asset_group_members WHERE asset_id=?`, []any{mergedID}},
		{`UPDATE asset_addresses SET asset_id=? WHERE asset_id=?`, []any{survivorID, mergedID}},
		{`UPDATE asset_names SET asset_id=? WHERE asset_id=?`, []any{survivorID, mergedID}},
		{`UPDATE asset_service_events SET asset_id=? WHERE asset_id=?`, []any{survivorID, mergedID}},
		{`UPDATE asset_evidence SET asset_id=? WHERE asset_id=?`, []any{survivorID, mergedID}},
	}
	for _, statement := range statements {
		if _, err := tx.Exec(statement.query, statement.args...); err != nil {
			return fmt.Errorf("transfer merged asset relationship: %w", err)
		}
	}
	return nil
}

func mergeAssetServices(tx *sql.Tx, survivorID, mergedID string) error {
	rows, err := tx.Query(`SELECT address,port,protocol,product,version,confidence,state,first_seen,last_seen,last_checked,last_scan_id,observation_count FROM asset_services WHERE asset_id=?`, mergedID)
	if err != nil {
		return fmt.Errorf("load merged asset services: %w", err)
	}
	services := []mergeServiceRecord{}
	for rows.Next() {
		var service mergeServiceRecord
		if err := rows.Scan(&service.Address, &service.Port, &service.Protocol, &service.Product, &service.Version,
			&service.Confidence, &service.State, &service.FirstSeen, &service.LastSeen, &service.LastChecked,
			&service.LastScanID, &service.ObservationCount); err != nil {
			_ = rows.Close()
			return err
		}
		services = append(services, service)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, service := range services {
		_, err := tx.Exec(`INSERT INTO asset_services(asset_id,address,port,protocol,product,version,confidence,state,first_seen,last_seen,last_checked,last_scan_id,observation_count) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(asset_id,address,port,protocol) DO UPDATE SET product=CASE WHEN excluded.last_checked>=asset_services.last_checked THEN excluded.product ELSE asset_services.product END,version=CASE WHEN excluded.last_checked>=asset_services.last_checked THEN excluded.version ELSE asset_services.version END,confidence=CASE WHEN excluded.last_checked>=asset_services.last_checked THEN excluded.confidence ELSE asset_services.confidence END,state=CASE WHEN excluded.last_checked>=asset_services.last_checked THEN excluded.state ELSE asset_services.state END,first_seen=MIN(asset_services.first_seen,excluded.first_seen),last_seen=MAX(asset_services.last_seen,excluded.last_seen),last_checked=MAX(asset_services.last_checked,excluded.last_checked),last_scan_id=CASE WHEN excluded.last_checked>=asset_services.last_checked THEN excluded.last_scan_id ELSE asset_services.last_scan_id END,observation_count=asset_services.observation_count+excluded.observation_count`, survivorID, service.Address, service.Port, service.Protocol, service.Product, service.Version, service.Confidence, service.State, service.FirstSeen, service.LastSeen, service.LastChecked, service.LastScanID, service.ObservationCount)
		if err != nil {
			return fmt.Errorf("merge asset service: %w", err)
		}
	}
	if _, err := tx.Exec(`DELETE FROM asset_services WHERE asset_id=?`, mergedID); err != nil {
		return fmt.Errorf("remove merged asset services: %w", err)
	}
	return nil
}
