package store

import (
	"database/sql"
	"errors"
	"time"

	"mossward/internal/model"
)

func (s *SQLiteStore) RecordEndpointNetworkInventory(endpointID string, inventory model.EndpointNetworkInventory, receivedAt time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.Exec(`INSERT INTO endpoint_network_inventory(endpoint_id,collected_at,received_at) SELECT id,?,? FROM endpoints WHERE id=? AND status='active'
		ON CONFLICT(endpoint_id) DO UPDATE SET collected_at=excluded.collected_at,received_at=excluded.received_at`, formatTime(inventory.CollectedAt), formatTime(receivedAt), endpointID)
	if err != nil {
		return err
	}
	changed, _ := result.RowsAffected()
	if changed != 1 {
		return ErrNotFound
	}
	if _, err := tx.Exec(`DELETE FROM endpoint_network_connections WHERE endpoint_id=?`, endpointID); err != nil {
		return err
	}
	for index, connection := range inventory.Connections {
		if _, err := tx.Exec(`INSERT INTO endpoint_network_connections(endpoint_id,ordinal,protocol,local_address,local_port,remote_address,remote_port,process_id,process_name,direction) VALUES(?,?,?,?,?,?,?,?,?,?)`,
			endpointID, index, connection.Protocol, connection.LocalAddress, connection.LocalPort, connection.RemoteAddress, connection.RemotePort, connection.ProcessID, connection.ProcessName, connection.Direction); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *SQLiteStore) EndpointNetworkInventory(endpointID string) (model.EndpointNetworkInventory, error) {
	var inventory model.EndpointNetworkInventory
	var collectedAt, receivedAt string
	err := s.db.QueryRow(`SELECT endpoint_id,collected_at,received_at FROM endpoint_network_inventory WHERE endpoint_id=?`, endpointID).Scan(&inventory.EndpointID, &collectedAt, &receivedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return inventory, ErrNotFound
	}
	if err != nil {
		return inventory, err
	}
	inventory.CollectedAt, _ = parseTime(collectedAt)
	inventory.ReceivedAt, _ = parseTime(receivedAt)
	rows, err := s.db.Query(`SELECT protocol,local_address,local_port,remote_address,remote_port,process_id,process_name,direction FROM endpoint_network_connections WHERE endpoint_id=? ORDER BY ordinal`, endpointID)
	if err != nil {
		return inventory, err
	}
	defer rows.Close()
	for rows.Next() {
		var connection model.NetworkConnection
		if err := rows.Scan(&connection.Protocol, &connection.LocalAddress, &connection.LocalPort, &connection.RemoteAddress, &connection.RemotePort, &connection.ProcessID, &connection.ProcessName, &connection.Direction); err != nil {
			return inventory, err
		}
		inventory.Connections = append(inventory.Connections, connection)
	}
	return inventory, rows.Err()
}
