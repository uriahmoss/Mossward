package store

import (
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"time"

	"mossward/internal/model"
)

type postgresMergeAssetRecord struct {
	ID               string
	Name             string
	Address          string
	FirstSeen        time.Time
	LastSeen         time.Time
	LastScanID       string
	Owner            string
	Environment      string
	Classification   string
	LifecycleStatus  string
	RetiredAt        sql.NullTime
	RetiredBy        string
	RetirementReason string
}

type postgresMergeServiceRecord struct {
	Address          string
	Port             int
	Protocol         string
	Product          string
	Version          string
	Confidence       string
	State            string
	FirstSeen        time.Time
	LastSeen         time.Time
	LastChecked      time.Time
	LastScanID       string
	ObservationCount int
}

func (s *PostgreSQLStore) MergeAssets(request model.AssetMergeRequest, event model.AuditEvent) error {
	if request.SurvivorID == "" || request.MergedID == "" || request.SurvivorID == request.MergedID {
		return errors.New("two different assets are required")
	}
	if !validMergeSources(request) {
		return errors.New("each selected value must come from one of the merged assets")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL asset merge: %w", err)
	}
	defer tx.Rollback()
	records, err := lockPostgreSQLMergeAssets(tx, request.SurvivorID, request.MergedID)
	if err != nil {
		return err
	}
	survivor := records[request.SurvivorID]
	merged := records[request.MergedID]
	selected := selectPostgreSQLMergedAsset(request, survivor, merged)
	if err := transferPostgreSQLAssetRelationships(tx, request.SurvivorID, request.MergedID); err != nil {
		return err
	}
	if err := mergePostgreSQLAssetServices(tx, request.SurvivorID, request.MergedID); err != nil {
		return err
	}
	firstSeen, lastSeen, lastScanID := mergedPostgreSQLAssetTimes(survivor, merged)
	if _, err := tx.Exec(`DELETE FROM assets WHERE id=$1`, request.MergedID); err != nil {
		return fmt.Errorf("remove PostgreSQL merged asset: %w", err)
	}
	_, err = tx.Exec(`UPDATE assets SET name=$1,address=$2,first_seen=$3,last_seen=$4,last_scan_id=$5,owner=$6,
		environment=$7,classification=$8,lifecycle_status=$9,retired_at=$10,retired_by=$11,retirement_reason=$12 WHERE id=$13`,
		selected.Name, selected.Address, firstSeen, lastSeen, lastScanID, selected.Owner, selected.Environment,
		selected.Classification, selected.LifecycleStatus, nullableMergeTime(selected.RetiredAt), selected.RetiredBy,
		selected.RetirementReason, request.SurvivorID)
	if err != nil {
		return fmt.Errorf("update PostgreSQL merged asset: %w", err)
	}
	if err := insertPostgreSQLAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func lockPostgreSQLMergeAssets(tx *sql.Tx, survivorID, mergedID string) (map[string]postgresMergeAssetRecord, error) {
	ids := []string{survivorID, mergedID}
	sort.Strings(ids)
	records := make(map[string]postgresMergeAssetRecord, len(ids))
	for _, id := range ids {
		record, err := loadPostgreSQLMergeAsset(tx, id)
		if err != nil {
			return nil, err
		}
		records[id] = record
	}
	return records, nil
}

func loadPostgreSQLMergeAsset(tx *sql.Tx, id string) (postgresMergeAssetRecord, error) {
	var asset postgresMergeAssetRecord
	err := tx.QueryRow(`SELECT id,name,address,first_seen,last_seen,last_scan_id,owner,environment,classification,
		lifecycle_status,retired_at,retired_by,retirement_reason FROM assets WHERE id=$1 FOR UPDATE`, id).
		Scan(&asset.ID, &asset.Name, &asset.Address, &asset.FirstSeen, &asset.LastSeen, &asset.LastScanID,
			&asset.Owner, &asset.Environment, &asset.Classification, &asset.LifecycleStatus, &asset.RetiredAt,
			&asset.RetiredBy, &asset.RetirementReason)
	if errors.Is(err, sql.ErrNoRows) {
		return asset, ErrAssetNotFound
	}
	if err != nil {
		return asset, fmt.Errorf("load PostgreSQL merge asset: %w", err)
	}
	return asset, nil
}

func selectPostgreSQLMergedAsset(request model.AssetMergeRequest, survivor, merged postgresMergeAssetRecord) postgresMergeAssetRecord {
	byID := map[string]postgresMergeAssetRecord{survivor.ID: survivor, merged.ID: merged}
	return postgresMergeAssetRecord{
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

func mergedPostgreSQLAssetTimes(survivor, merged postgresMergeAssetRecord) (time.Time, time.Time, string) {
	firstSeen := survivor.FirstSeen
	if merged.FirstSeen.Before(firstSeen) {
		firstSeen = merged.FirstSeen
	}
	lastSeen := survivor.LastSeen
	lastScanID := survivor.LastScanID
	if merged.LastSeen.After(lastSeen) {
		lastSeen = merged.LastSeen
		lastScanID = merged.LastScanID
	}
	return firstSeen, lastSeen, lastScanID
}

func nullableMergeTime(value sql.NullTime) any {
	if !value.Valid {
		return nil
	}
	return value.Time
}

func transferPostgreSQLAssetRelationships(tx *sql.Tx, survivorID, mergedID string) error {
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO asset_group_members(group_id,asset_id,added_at,added_by)
			SELECT group_id,$1,added_at,added_by FROM asset_group_members WHERE asset_id=$2
			ON CONFLICT(group_id,asset_id) DO NOTHING`, []any{survivorID, mergedID}},
		{`DELETE FROM asset_group_members WHERE asset_id=$1`, []any{mergedID}},
		{`UPDATE asset_addresses SET asset_id=$1 WHERE asset_id=$2`, []any{survivorID, mergedID}},
		{`UPDATE asset_names SET asset_id=$1 WHERE asset_id=$2`, []any{survivorID, mergedID}},
		{`UPDATE asset_service_events SET asset_id=$1 WHERE asset_id=$2`, []any{survivorID, mergedID}},
		{`UPDATE asset_evidence SET asset_id=$1 WHERE asset_id=$2`, []any{survivorID, mergedID}},
	}
	for _, statement := range statements {
		if _, err := tx.Exec(statement.query, statement.args...); err != nil {
			return fmt.Errorf("transfer PostgreSQL merged asset relationship: %w", err)
		}
	}
	return nil
}

func mergePostgreSQLAssetServices(tx *sql.Tx, survivorID, mergedID string) error {
	rows, err := tx.Query(`SELECT address,port,protocol,product,version,confidence,state,first_seen,last_seen,
		last_checked,last_scan_id,observation_count FROM asset_services WHERE asset_id=$1`, mergedID)
	if err != nil {
		return fmt.Errorf("load PostgreSQL merged asset services: %w", err)
	}
	services := []postgresMergeServiceRecord{}
	for rows.Next() {
		var service postgresMergeServiceRecord
		if err := rows.Scan(&service.Address, &service.Port, &service.Protocol, &service.Product, &service.Version,
			&service.Confidence, &service.State, &service.FirstSeen, &service.LastSeen, &service.LastChecked,
			&service.LastScanID, &service.ObservationCount); err != nil {
			_ = rows.Close()
			return fmt.Errorf("read PostgreSQL merged asset service: %w", err)
		}
		services = append(services, service)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, service := range services {
		if err := mergePostgreSQLAssetService(tx, survivorID, service); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`DELETE FROM asset_services WHERE asset_id=$1`, mergedID); err != nil {
		return fmt.Errorf("remove PostgreSQL merged asset services: %w", err)
	}
	return nil
}

func mergePostgreSQLAssetService(tx *sql.Tx, survivorID string, service postgresMergeServiceRecord) error {
	_, err := tx.Exec(`INSERT INTO asset_services(asset_id,address,port,protocol,product,version,confidence,state,
		first_seen,last_seen,last_checked,last_scan_id,observation_count) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
		ON CONFLICT(asset_id,address,port,protocol) DO UPDATE SET
		product=CASE WHEN EXCLUDED.last_checked>=asset_services.last_checked THEN EXCLUDED.product ELSE asset_services.product END,
		version=CASE WHEN EXCLUDED.last_checked>=asset_services.last_checked THEN EXCLUDED.version ELSE asset_services.version END,
		confidence=CASE WHEN EXCLUDED.last_checked>=asset_services.last_checked THEN EXCLUDED.confidence ELSE asset_services.confidence END,
		state=CASE WHEN EXCLUDED.last_checked>=asset_services.last_checked THEN EXCLUDED.state ELSE asset_services.state END,
		first_seen=LEAST(asset_services.first_seen,EXCLUDED.first_seen),last_seen=GREATEST(asset_services.last_seen,EXCLUDED.last_seen),
		last_checked=GREATEST(asset_services.last_checked,EXCLUDED.last_checked),
		last_scan_id=CASE WHEN EXCLUDED.last_checked>=asset_services.last_checked THEN EXCLUDED.last_scan_id ELSE asset_services.last_scan_id END,
		observation_count=asset_services.observation_count+EXCLUDED.observation_count`, survivorID, service.Address,
		service.Port, service.Protocol, service.Product, service.Version, service.Confidence, service.State,
		service.FirstSeen, service.LastSeen, service.LastChecked, service.LastScanID, service.ObservationCount)
	if err != nil {
		return fmt.Errorf("merge PostgreSQL asset service: %w", err)
	}
	return nil
}
