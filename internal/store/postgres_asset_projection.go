package store

import (
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"time"

	"mossward/internal/model"
)

func projectPostgreSQLScanAssets(tx *sql.Tx, scan model.Scan) error {
	if scan.Status != model.StatusCompleted {
		return nil
	}
	for _, observation := range scan.Observations {
		if err := projectPostgreSQLObservationAsset(tx, scan, observation); err != nil {
			return err
		}
	}
	return nil
}

func projectPostgreSQLObservationAsset(tx *sql.Tx, scan model.Scan, observation model.ServiceObservation) error {
	observedAt := observation.ObservedAt
	if observedAt.IsZero() {
		observedAt = completedOrCreatedAt(scan)
	}
	normalizedName := normalizedAssetName(observation.Target)
	if err := lockPostgreSQLAssetIdentity(tx, observation.Address, normalizedName); err != nil {
		return err
	}
	assetID, err := correlatedPostgreSQLAssetID(tx, observation.Address, normalizedName)
	if err != nil {
		return err
	}
	if assetID == "" {
		assetID = assetIDForAddress(observation.Address)
	}
	_, err = tx.Exec(`INSERT INTO assets(id,name,address,first_seen,last_seen,last_scan_id) VALUES($1,$2,$3,$4,$5,$6)
		ON CONFLICT(id) DO UPDATE SET name=EXCLUDED.name,last_seen=EXCLUDED.last_seen,last_scan_id=EXCLUDED.last_scan_id
		WHERE EXCLUDED.last_seen>=assets.last_seen`, assetID, observation.Target, observation.Address, observedAt, observedAt, scan.ID)
	if err != nil {
		return fmt.Errorf("upsert PostgreSQL discovered asset: %w", err)
	}
	if err := upsertPostgreSQLAssetAddress(tx, assetID, observation.Address, observedAt, scan.ID); err != nil {
		return err
	}
	return addPostgreSQLAssetName(tx, assetID, observation.Target, normalizedName)
}

func lockPostgreSQLAssetIdentity(tx *sql.Tx, address, normalizedName string) error {
	keys := []string{"address:" + address}
	if normalizedName != "" {
		keys = append(keys, "name:"+normalizedName)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if _, err := tx.Exec(`SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, key); err != nil {
			return fmt.Errorf("lock PostgreSQL asset identity: %w", err)
		}
	}
	return nil
}

func correlatedPostgreSQLAssetID(tx *sql.Tx, address, normalizedName string) (string, error) {
	addressID, err := lookupPostgreSQLAssetID(tx, `SELECT asset_id FROM asset_addresses WHERE address=$1`, address)
	if err != nil || normalizedName == "" {
		return addressID, err
	}
	nameID, err := lookupPostgreSQLAssetID(tx, `SELECT asset_id FROM asset_names WHERE normalized_name=$1`, normalizedName)
	if err != nil {
		return "", err
	}
	if addressID != "" {
		return addressID, nil
	}
	return nameID, nil
}

func lookupPostgreSQLAssetID(tx *sql.Tx, query, value string) (string, error) {
	var id string
	err := tx.QueryRow(query, value).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("look up PostgreSQL asset identity: %w", err)
	}
	return id, nil
}

func upsertPostgreSQLAssetAddress(tx *sql.Tx, assetID, address string, observedAt time.Time, scanID string) error {
	_, err := tx.Exec(`INSERT INTO asset_addresses(asset_id,address,first_seen,last_seen,last_scan_id) VALUES($1,$2,$3,$4,$5)
		ON CONFLICT(address) DO UPDATE SET last_seen=EXCLUDED.last_seen,last_scan_id=EXCLUDED.last_scan_id
		WHERE EXCLUDED.asset_id=asset_addresses.asset_id AND EXCLUDED.last_seen>=asset_addresses.last_seen`,
		assetID, address, observedAt, observedAt, scanID)
	if err != nil {
		return fmt.Errorf("upsert PostgreSQL asset address: %w", err)
	}
	return nil
}

func addPostgreSQLAssetName(tx *sql.Tx, assetID, name, normalizedName string) error {
	if normalizedName == "" {
		return nil
	}
	_, err := tx.Exec(`INSERT INTO asset_names(asset_id,name,normalized_name) VALUES($1,$2,$3)
		ON CONFLICT(normalized_name) DO NOTHING`, assetID, name, normalizedName)
	if err != nil {
		return fmt.Errorf("add PostgreSQL asset name: %w", err)
	}
	return nil
}
