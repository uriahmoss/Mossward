package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"mossward/internal/model"
)

func (s *SQLiteStore) RecordEndpointOSInventory(endpointID string, inventory model.EndpointOSInventory, receivedAt time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.Exec(`INSERT INTO endpoint_os_inventory(endpoint_id,family,name,version,build,kernel,architecture,collected_at,received_at)
		SELECT id,?,?,?,?,?,?,?,? FROM endpoints WHERE id=? AND status='active'
		ON CONFLICT(endpoint_id) DO UPDATE SET family=excluded.family,name=excluded.name,version=excluded.version,build=excluded.build,kernel=excluded.kernel,architecture=excluded.architecture,collected_at=excluded.collected_at,received_at=excluded.received_at`,
		inventory.Family, inventory.Name, inventory.Version, inventory.Build, inventory.Kernel, inventory.Architecture, formatTime(inventory.CollectedAt), formatTime(receivedAt), endpointID)
	if err != nil {
		return fmt.Errorf("record endpoint OS inventory: %w", err)
	}
	changed, _ := result.RowsAffected()
	if changed != 1 {
		return ErrNotFound
	}
	if _, err := tx.Exec(`DELETE FROM endpoint_os_patches WHERE endpoint_id=?`, endpointID); err != nil {
		return err
	}
	for _, patch := range inventory.Patches {
		if _, err := tx.Exec(`INSERT INTO endpoint_os_patches(endpoint_id,patch_id,description,installed_at) VALUES(?,?,?,?)`, endpointID, patch.ID, patch.Description, formatOptionalTime(patch.InstalledAt)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *SQLiteStore) EndpointOSInventory(endpointID string) (model.EndpointOSInventory, error) {
	var inventory model.EndpointOSInventory
	var collectedAt, receivedAt string
	err := s.db.QueryRow(`SELECT endpoint_id,family,name,version,build,kernel,architecture,collected_at,received_at FROM endpoint_os_inventory WHERE endpoint_id=?`, endpointID).
		Scan(&inventory.EndpointID, &inventory.Family, &inventory.Name, &inventory.Version, &inventory.Build, &inventory.Kernel, &inventory.Architecture, &collectedAt, &receivedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return inventory, ErrNotFound
	}
	if err != nil {
		return inventory, err
	}
	inventory.CollectedAt, _ = parseTime(collectedAt)
	inventory.ReceivedAt, _ = parseTime(receivedAt)
	rows, err := s.db.Query(`SELECT patch_id,description,installed_at FROM endpoint_os_patches WHERE endpoint_id=? ORDER BY patch_id`, endpointID)
	if err != nil {
		return inventory, err
	}
	defer rows.Close()
	for rows.Next() {
		var patch model.EndpointPatch
		var installedAt sql.NullString
		if err := rows.Scan(&patch.ID, &patch.Description, &installedAt); err != nil {
			return inventory, err
		}
		patch.InstalledAt = parseNullableTime(installedAt)
		inventory.Patches = append(inventory.Patches, patch)
	}
	return inventory, rows.Err()
}
