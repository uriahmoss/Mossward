package store

import (
	"database/sql"
	"errors"
	"time"

	"mossward/internal/model"
)

func (s *SQLiteStore) RecordEndpointSoftwareInventory(endpointID string, inventory model.EndpointSoftwareInventory, receivedAt time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.Exec(`INSERT INTO endpoint_software_inventory(endpoint_id,collected_at,received_at) SELECT id,?,? FROM endpoints WHERE id=? AND status='active'
		ON CONFLICT(endpoint_id) DO UPDATE SET collected_at=excluded.collected_at,received_at=excluded.received_at`, formatTime(inventory.CollectedAt), formatTime(receivedAt), endpointID)
	if err != nil {
		return err
	}
	changed, _ := result.RowsAffected()
	if changed != 1 {
		return ErrNotFound
	}
	if _, err := tx.Exec(`DELETE FROM endpoint_installed_software WHERE endpoint_id=?`, endpointID); err != nil {
		return err
	}
	for index, item := range inventory.Items {
		if _, err := tx.Exec(`INSERT INTO endpoint_installed_software(endpoint_id,ordinal,name,version,publisher,architecture,source) VALUES(?,?,?,?,?,?,?)`, endpointID, index, item.Name, item.Version, item.Publisher, item.Architecture, item.Source); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *SQLiteStore) EndpointSoftwareInventory(endpointID string) (model.EndpointSoftwareInventory, error) {
	var inventory model.EndpointSoftwareInventory
	var collectedAt, receivedAt string
	err := s.db.QueryRow(`SELECT endpoint_id,collected_at,received_at FROM endpoint_software_inventory WHERE endpoint_id=?`, endpointID).Scan(&inventory.EndpointID, &collectedAt, &receivedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return inventory, ErrNotFound
	}
	if err != nil {
		return inventory, err
	}
	inventory.CollectedAt, _ = parseTime(collectedAt)
	inventory.ReceivedAt, _ = parseTime(receivedAt)
	rows, err := s.db.Query(`SELECT name,version,publisher,architecture,source FROM endpoint_installed_software WHERE endpoint_id=? ORDER BY ordinal`, endpointID)
	if err != nil {
		return inventory, err
	}
	defer rows.Close()
	for rows.Next() {
		var item model.InstalledSoftware
		if err := rows.Scan(&item.Name, &item.Version, &item.Publisher, &item.Architecture, &item.Source); err != nil {
			return inventory, err
		}
		inventory.Items = append(inventory.Items, item)
	}
	return inventory, rows.Err()
}
