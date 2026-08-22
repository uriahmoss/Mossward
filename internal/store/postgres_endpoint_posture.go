package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"mossward/internal/model"
)

func (s *PostgreSQLStore) RecordEndpointListeningInventory(endpointID string, inventory model.EndpointListeningInventory, receivedAt time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL endpoint listening inventory: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.Exec(`INSERT INTO endpoint_listening_inventory(endpoint_id,collected_at,received_at)
		SELECT id,$1,$2 FROM endpoints WHERE id=$3 AND status='active'
		ON CONFLICT(endpoint_id) DO UPDATE SET collected_at=EXCLUDED.collected_at,received_at=EXCLUDED.received_at`,
		inventory.CollectedAt, receivedAt, endpointID)
	if err != nil {
		return fmt.Errorf("record PostgreSQL endpoint listening inventory: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return ErrNotFound
	}
	if _, err := tx.Exec(`DELETE FROM endpoint_listening_services WHERE endpoint_id=$1`, endpointID); err != nil {
		return fmt.Errorf("replace PostgreSQL endpoint listening services: %w", err)
	}
	for ordinal, service := range inventory.Services {
		_, err := tx.Exec(`INSERT INTO endpoint_listening_services(endpoint_id,ordinal,protocol,address,port,process_id,process_name,executable)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, endpointID, ordinal, service.Protocol, service.Address,
			service.Port, service.ProcessID, service.ProcessName, service.Executable)
		if err != nil {
			return fmt.Errorf("record PostgreSQL endpoint listening service: %w", err)
		}
	}
	return tx.Commit()
}

func (s *PostgreSQLStore) EndpointListeningInventory(endpointID string) (model.EndpointListeningInventory, error) {
	var inventory model.EndpointListeningInventory
	err := s.db.QueryRow(`SELECT endpoint_id,collected_at,received_at FROM endpoint_listening_inventory WHERE endpoint_id=$1`, endpointID).
		Scan(&inventory.EndpointID, &inventory.CollectedAt, &inventory.ReceivedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return inventory, ErrNotFound
	}
	if err != nil {
		return inventory, fmt.Errorf("load PostgreSQL endpoint listening inventory: %w", err)
	}
	rows, err := s.db.Query(`SELECT protocol,address,port,process_id,process_name,executable
		FROM endpoint_listening_services WHERE endpoint_id=$1 ORDER BY ordinal`, endpointID)
	if err != nil {
		return inventory, fmt.Errorf("load PostgreSQL endpoint listening services: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var service model.ListeningService
		if err := rows.Scan(&service.Protocol, &service.Address, &service.Port, &service.ProcessID,
			&service.ProcessName, &service.Executable); err != nil {
			return inventory, fmt.Errorf("read PostgreSQL endpoint listening service: %w", err)
		}
		inventory.Services = append(inventory.Services, service)
	}
	return inventory, rows.Err()
}

func (s *PostgreSQLStore) RecordEndpointPostureInventory(endpointID string, inventory model.EndpointPostureInventory, receivedAt time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL endpoint posture inventory: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.Exec(`INSERT INTO endpoint_posture_inventory(endpoint_id,collected_at,received_at)
		SELECT id,$1,$2 FROM endpoints WHERE id=$3 AND status='active'
		ON CONFLICT(endpoint_id) DO UPDATE SET collected_at=EXCLUDED.collected_at,received_at=EXCLUDED.received_at`,
		inventory.CollectedAt, receivedAt, endpointID)
	if err != nil {
		return fmt.Errorf("record PostgreSQL endpoint posture inventory: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return ErrNotFound
	}
	if _, err := tx.Exec(`DELETE FROM endpoint_posture_evidence WHERE endpoint_id=$1`, endpointID); err != nil {
		return fmt.Errorf("replace PostgreSQL endpoint posture evidence: %w", err)
	}
	for _, evidence := range inventory.Evidence {
		_, err := tx.Exec(`INSERT INTO endpoint_posture_evidence(endpoint_id,evidence_id,title,status,detail)
			VALUES($1,$2,$3,$4,$5)`, endpointID, evidence.ID, evidence.Title, evidence.Status, evidence.Detail)
		if err != nil {
			return fmt.Errorf("record PostgreSQL endpoint posture evidence: %w", err)
		}
	}
	return tx.Commit()
}

func (s *PostgreSQLStore) EndpointPostureInventory(endpointID string) (model.EndpointPostureInventory, error) {
	var inventory model.EndpointPostureInventory
	err := s.db.QueryRow(`SELECT endpoint_id,collected_at,received_at FROM endpoint_posture_inventory WHERE endpoint_id=$1`, endpointID).
		Scan(&inventory.EndpointID, &inventory.CollectedAt, &inventory.ReceivedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return inventory, ErrNotFound
	}
	if err != nil {
		return inventory, fmt.Errorf("load PostgreSQL endpoint posture inventory: %w", err)
	}
	rows, err := s.db.Query(`SELECT evidence_id,title,status,detail FROM endpoint_posture_evidence
		WHERE endpoint_id=$1 ORDER BY evidence_id`, endpointID)
	if err != nil {
		return inventory, fmt.Errorf("load PostgreSQL endpoint posture evidence: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var evidence model.PostureEvidence
		if err := rows.Scan(&evidence.ID, &evidence.Title, &evidence.Status, &evidence.Detail); err != nil {
			return inventory, fmt.Errorf("read PostgreSQL endpoint posture evidence: %w", err)
		}
		inventory.Evidence = append(inventory.Evidence, evidence)
	}
	return inventory, rows.Err()
}
