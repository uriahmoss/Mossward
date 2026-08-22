package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"mossward/internal/model"
)

func (s *PostgreSQLStore) AssetDetail(id string, now time.Time) (model.AssetDetail, error) {
	assets, err := s.ListAssets()
	if err != nil {
		return model.AssetDetail{}, err
	}
	var detail model.AssetDetail
	for _, asset := range assets {
		if asset.ID == id {
			detail.Asset = asset
			break
		}
	}
	if detail.Asset.ID == "" {
		return detail, ErrAssetNotFound
	}
	detail.Services, err = s.loadPostgreSQLAssetServices(id, now)
	if err != nil {
		return detail, err
	}
	detail.Evidence, err = s.loadPostgreSQLAssetEvidence(id)
	return detail, err
}

func (s *PostgreSQLStore) loadPostgreSQLAssetServices(assetID string, now time.Time) ([]model.AssetService, error) {
	rows, err := s.db.Query(`SELECT address,port,protocol,product,version,confidence,state,first_seen,last_seen,last_checked,
		last_scan_id,observation_count FROM asset_services WHERE asset_id=$1 ORDER BY state,port,protocol`, assetID)
	if err != nil {
		return nil, fmt.Errorf("load PostgreSQL asset services: %w", err)
	}
	services := []model.AssetService{}
	for rows.Next() {
		var service model.AssetService
		if err := rows.Scan(&service.Address, &service.Port, &service.Protocol, &service.Product, &service.Version,
			&service.Confidence, &service.State, &service.FirstSeen, &service.LastSeen, &service.LastChecked,
			&service.LastScanID, &service.ObservationCount); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("read PostgreSQL asset service: %w", err)
		}
		if service.State == model.AssetServiceObserved && now.Sub(service.LastChecked) >= assetServiceStaleAfter {
			service.State = model.AssetServiceStale
		}
		services = append(services, service)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for index := range services {
		services[index].Events, err = s.loadPostgreSQLAssetServiceEvents(assetID, services[index])
		if err != nil {
			return nil, err
		}
	}
	return services, nil
}

func (s *PostgreSQLStore) loadPostgreSQLAssetServiceEvents(assetID string, service model.AssetService) ([]model.AssetServiceEvent, error) {
	rows, err := s.db.Query(`SELECT observation_id,scan_id,product,version,confidence,observed_at,finding_ids,cve_ids,
		source_type,source_id FROM asset_service_events WHERE asset_id=$1 AND address=$2 AND port=$3 AND protocol=$4
		ORDER BY observed_at DESC`, assetID, service.Address, service.Port, service.Protocol)
	if err != nil {
		return nil, fmt.Errorf("load PostgreSQL asset service events: %w", err)
	}
	defer rows.Close()
	events := []model.AssetServiceEvent{}
	for rows.Next() {
		var event model.AssetServiceEvent
		var findingIDs, cveIDs []byte
		if err := rows.Scan(&event.ObservationID, &event.ScanID, &event.Product, &event.Version, &event.Confidence,
			&event.ObservedAt, &findingIDs, &cveIDs, &event.Provenance.SourceType, &event.Provenance.SourceID); err != nil {
			return nil, fmt.Errorf("read PostgreSQL asset service event: %w", err)
		}
		if err := json.Unmarshal(findingIDs, &event.FindingIDs); err != nil {
			return nil, fmt.Errorf("decode PostgreSQL service-event findings: %w", err)
		}
		if err := json.Unmarshal(cveIDs, &event.CVEIDs); err != nil {
			return nil, fmt.Errorf("decode PostgreSQL service-event CVEs: %w", err)
		}
		event.Provenance.RecordType = "service_observation"
		event.Provenance.RecordID = event.ObservationID
		event.Provenance.CollectedAt = event.ObservedAt
		events = append(events, event)
	}
	return events, rows.Err()
}

func (s *PostgreSQLStore) RecordAssetEvidence(evidence model.AssetEvidence) error {
	if err := validateAssetEvidence(evidence); err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL asset evidence update: %w", err)
	}
	defer tx.Rollback()
	if err := insertPostgreSQLAssetEvidence(tx, evidence); err != nil {
		return err
	}
	return tx.Commit()
}

func insertPostgreSQLAssetEvidence(tx *sql.Tx, evidence model.AssetEvidence) error {
	_, err := tx.Exec(`INSERT INTO asset_evidence(id,asset_id,source_type,source_id,record_type,record_id,scan_id,address,
		summary,collected_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		ON CONFLICT(source_type,source_id,record_type,record_id) DO NOTHING`, evidence.ID, evidence.AssetID,
		evidence.SourceType, evidence.SourceID, evidence.RecordType, evidence.RecordID, evidence.ScanID, evidence.Address,
		evidence.Summary, evidence.CollectedAt)
	if err != nil {
		return fmt.Errorf("record PostgreSQL asset evidence provenance: %w", err)
	}
	return nil
}

func (s *PostgreSQLStore) loadPostgreSQLAssetEvidence(assetID string) ([]model.AssetEvidence, error) {
	rows, err := s.db.Query(`SELECT id,source_type,source_id,record_type,record_id,scan_id,address,summary,collected_at
		FROM asset_evidence WHERE asset_id=$1 ORDER BY collected_at DESC`, assetID)
	if err != nil {
		return nil, fmt.Errorf("load PostgreSQL asset evidence: %w", err)
	}
	defer rows.Close()
	evidence := []model.AssetEvidence{}
	for rows.Next() {
		var item model.AssetEvidence
		item.AssetID = assetID
		if err := rows.Scan(&item.ID, &item.SourceType, &item.SourceID, &item.RecordType, &item.RecordID, &item.ScanID,
			&item.Address, &item.Summary, &item.CollectedAt); err != nil {
			return nil, fmt.Errorf("read PostgreSQL asset evidence: %w", err)
		}
		evidence = append(evidence, item)
	}
	return evidence, rows.Err()
}
