package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"mossward/internal/model"
)

const assetIDBytes = 16

func upsertScanAssets(tx *sql.Tx, scan model.Scan) error {
	if scan.Status != model.StatusCompleted {
		return nil
	}
	for _, observation := range scan.Observations {
		if err := upsertObservationAsset(tx, scan, observation); err != nil {
			return err
		}
	}
	return nil
}

func upsertObservationAsset(tx *sql.Tx, scan model.Scan, observation model.ServiceObservation) error {
	observedAt := observation.ObservedAt
	if observedAt.IsZero() {
		observedAt = completedOrCreatedAt(scan)
	}
	normalizedName := normalizedAssetName(observation.Target)
	assetID, err := correlatedAssetID(tx, observation.Address, normalizedName)
	if err != nil {
		return err
	}
	if assetID == "" {
		assetID = assetIDForAddress(observation.Address)
	}
	_, err = tx.Exec(`INSERT INTO assets(id,name,address,first_seen,last_seen,last_scan_id) VALUES(?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET name=excluded.name,last_seen=excluded.last_seen,last_scan_id=excluded.last_scan_id
		WHERE excluded.last_seen >= assets.last_seen`, assetID, observation.Target, observation.Address,
		formatTime(observedAt), formatTime(observedAt), scan.ID)
	if err != nil {
		return fmt.Errorf("upsert discovered asset: %w", err)
	}
	if err := upsertAssetAddress(tx, assetID, observation.Address, observedAt, scan.ID); err != nil {
		return err
	}
	return addAssetName(tx, assetID, observation.Target, normalizedName)
}

func correlatedAssetID(tx *sql.Tx, address, normalizedName string) (string, error) {
	addressID, err := lookupAssetID(tx, `SELECT asset_id FROM asset_addresses WHERE address=?`, address)
	if err != nil || normalizedName == "" {
		return addressID, err
	}
	nameID, err := lookupAssetID(tx, `SELECT asset_id FROM asset_names WHERE normalized_name=?`, normalizedName)
	if err != nil {
		return "", err
	}
	if addressID != "" {
		return addressID, nil
	}
	return nameID, nil
}

func lookupAssetID(tx *sql.Tx, query, value string) (string, error) {
	var id string
	err := tx.QueryRow(query, value).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return id, err
}

func upsertAssetAddress(tx *sql.Tx, assetID, address string, observedAt time.Time, scanID string) error {
	_, err := tx.Exec(`INSERT INTO asset_addresses(asset_id,address,first_seen,last_seen,last_scan_id) VALUES(?,?,?,?,?)
		ON CONFLICT(address) DO UPDATE SET last_seen=excluded.last_seen,last_scan_id=excluded.last_scan_id
		WHERE excluded.asset_id=asset_addresses.asset_id AND excluded.last_seen >= asset_addresses.last_seen`,
		assetID, address, formatTime(observedAt), formatTime(observedAt), scanID)
	if err != nil {
		return fmt.Errorf("upsert asset address: %w", err)
	}
	return nil
}

func addAssetName(tx *sql.Tx, assetID, name, normalizedName string) error {
	if normalizedName == "" {
		return nil
	}
	_, err := tx.Exec(`INSERT INTO asset_names(asset_id,name,normalized_name) VALUES(?,?,?) ON CONFLICT(normalized_name) DO NOTHING`,
		assetID, name, normalizedName)
	if err != nil {
		return fmt.Errorf("add asset name: %w", err)
	}
	return nil
}

func normalizedAssetName(value string) string {
	name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if name == "" || !strings.Contains(name, ".") {
		return ""
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return ""
	}
	if _, err := netip.ParsePrefix(name); err == nil {
		return ""
	}
	labels := strings.Split(name, ".")
	for _, label := range labels {
		if !validDNSLabel(label) {
			return ""
		}
	}
	return name
}

func validDNSLabel(label string) bool {
	if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, character := range label {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}

func completedOrCreatedAt(scan model.Scan) time.Time {
	if scan.CompletedAt != nil {
		return *scan.CompletedAt
	}
	return scan.CreatedAt
}

func assetIDForAddress(address string) string {
	digest := sha256.Sum256([]byte(address))
	return hex.EncodeToString(digest[:assetIDBytes])
}

func (s *SQLiteStore) ListAssets() ([]model.Asset, error) {
	rows, err := s.db.Query(`SELECT id,name,address,first_seen,last_seen,last_scan_id,owner,environment,classification FROM assets ORDER BY last_seen DESC,name`)
	if err != nil {
		return nil, fmt.Errorf("list assets: %w", err)
	}
	assets := []model.Asset{}
	for rows.Next() {
		var asset model.Asset
		var firstSeen, lastSeen string
		if err := rows.Scan(&asset.ID, &asset.Name, &asset.Address, &firstSeen, &lastSeen, &asset.LastScanID,
			&asset.Owner, &asset.Environment, &asset.Classification); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("read asset: %w", err)
		}
		asset.FirstSeen, _ = parseTime(firstSeen)
		asset.LastSeen, _ = parseTime(lastSeen)
		assets = append(assets, asset)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close assets: %w", err)
	}
	for index := range assets {
		if err := s.loadAssetIdentity(&assets[index]); err != nil {
			return nil, err
		}
	}
	return assets, nil
}

func (s *SQLiteStore) UpdateAssetMetadata(id string, metadata model.AssetMetadata, event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin asset metadata update: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.Exec(`UPDATE assets SET owner=?,environment=?,classification=? WHERE id=?`,
		metadata.Owner, metadata.Environment, metadata.Classification, id)
	if err != nil {
		return fmt.Errorf("update asset metadata: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return ErrAssetNotFound
	}
	if err := insertAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLiteStore) loadAssetIdentity(asset *model.Asset) error {
	asset.Names = []string{}
	nameRows, err := s.db.Query(`SELECT name FROM asset_names WHERE asset_id=? ORDER BY name`, asset.ID)
	if err != nil {
		return fmt.Errorf("load asset names: %w", err)
	}
	for nameRows.Next() {
		var name string
		if err := nameRows.Scan(&name); err != nil {
			_ = nameRows.Close()
			return err
		}
		asset.Names = append(asset.Names, name)
	}
	if err := nameRows.Close(); err != nil {
		return err
	}
	addressRows, err := s.db.Query(`SELECT address,first_seen,last_seen,last_scan_id FROM asset_addresses WHERE asset_id=? ORDER BY address`, asset.ID)
	if err != nil {
		return fmt.Errorf("load asset addresses: %w", err)
	}
	defer addressRows.Close()
	asset.Addresses = []model.AssetAddress{}
	for addressRows.Next() {
		var address model.AssetAddress
		var firstSeen, lastSeen string
		if err := addressRows.Scan(&address.Address, &firstSeen, &lastSeen, &address.LastScanID); err != nil {
			return err
		}
		address.FirstSeen, _ = parseTime(firstSeen)
		address.LastSeen, _ = parseTime(lastSeen)
		asset.Addresses = append(asset.Addresses, address)
	}
	return addressRows.Err()
}
