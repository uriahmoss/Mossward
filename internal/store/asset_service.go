package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"mossward/internal/model"
	"time"
)

const (
	assetServiceStaleAfter = 30 * 24 * time.Hour
	localScannerSourceID   = "scanner/local"
	evidenceIdentityLimit  = 200
	evidenceSummaryLimit   = 1000
)

func updateAssetServiceHistory(tx *sql.Tx, scan model.Scan) error {
	if scan.Status != model.StatusCompleted {
		return nil
	}
	checkedAt := completedOrCreatedAt(scan)
	for _, target := range scan.Targets {
		for _, port := range scan.Ports {
			if _, err := tx.Exec(`UPDATE asset_services SET state='not_observed',last_checked=?,last_scan_id=? WHERE address=? AND port=? AND last_checked<=?`, formatTime(checkedAt), scan.ID, target.Address, port, formatTime(checkedAt)); err != nil {
				return fmt.Errorf("mark service not observed: %w", err)
			}
		}
	}
	sourceID, err := scannerEvidenceSourceID(tx, scan.ID)
	if err != nil {
		return err
	}
	for _, observation := range scan.Observations {
		if err := recordAssetServiceObservation(tx, scan, observation, checkedAt, sourceID); err != nil {
			return err
		}
	}
	return nil
}

func recordAssetServiceObservation(tx *sql.Tx, scan model.Scan, observation model.ServiceObservation, checkedAt time.Time, sourceID string) error {
	assetID, err := lookupAssetID(tx, `SELECT asset_id FROM asset_addresses WHERE address=?`, observation.Address)
	if err != nil {
		return err
	}
	if assetID == "" {
		return nil
	}
	findingIDs := []string{}
	for _, finding := range scan.Findings {
		if finding.Address == observation.Address && finding.Port == observation.Port {
			findingIDs = append(findingIDs, finding.ID)
		}
	}
	cveIDs := []string{}
	for _, match := range scan.CVEMatches {
		if match.ObservationID == observation.ID {
			cveIDs = append(cveIDs, match.CVEID)
		}
	}
	findingsJSON, _ := json.Marshal(findingIDs)
	cvesJSON, _ := json.Marshal(cveIDs)
	collectedAt := observation.ObservedAt
	if collectedAt.IsZero() {
		collectedAt = checkedAt
	}
	result, err := tx.Exec(`INSERT INTO asset_service_events(observation_id,asset_id,scan_id,address,port,protocol,product,version,confidence,observed_at,finding_ids,cve_ids,source_type,source_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(observation_id) DO NOTHING`, observation.ID, assetID, scan.ID, observation.Address, observation.Port, observation.Protocol, observation.Product, observation.Version, observation.Confidence, formatTime(collectedAt), findingsJSON, cvesJSON, model.EvidenceSourceScanner, sourceID)
	if err != nil {
		return fmt.Errorf("record asset service event: %w", err)
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("count asset service event: %w", err)
	}
	increment := 0
	if inserted == 1 {
		increment = 1
	}
	_, err = tx.Exec(`INSERT INTO asset_services(asset_id,address,port,protocol,product,version,confidence,state,first_seen,last_seen,last_checked,last_scan_id,observation_count) VALUES(?,?,?,?,?,?,?,'observed',?,?,?,?,1) ON CONFLICT(asset_id,address,port,protocol) DO UPDATE SET product=CASE WHEN excluded.last_checked>=asset_services.last_checked THEN excluded.product ELSE asset_services.product END,version=CASE WHEN excluded.last_checked>=asset_services.last_checked THEN excluded.version ELSE asset_services.version END,confidence=CASE WHEN excluded.last_checked>=asset_services.last_checked THEN excluded.confidence ELSE asset_services.confidence END,state=CASE WHEN excluded.last_checked>=asset_services.last_checked THEN 'observed' ELSE asset_services.state END,last_seen=MAX(asset_services.last_seen,excluded.last_seen),last_checked=MAX(asset_services.last_checked,excluded.last_checked),last_scan_id=CASE WHEN excluded.last_checked>=asset_services.last_checked THEN excluded.last_scan_id ELSE asset_services.last_scan_id END,observation_count=asset_services.observation_count+?`, assetID, observation.Address, observation.Port, observation.Protocol, observation.Product, observation.Version, observation.Confidence, formatTime(collectedAt), formatTime(collectedAt), formatTime(checkedAt), scan.ID, increment)
	if err != nil {
		return fmt.Errorf("update asset service: %w", err)
	}
	evidence := model.AssetEvidence{ID: "scanner:" + observation.ID, AssetID: assetID, ScanID: scan.ID, Address: observation.Address,
		Summary: fmt.Sprintf("%s service observed on port %d", observation.Protocol, observation.Port),
		EvidenceProvenance: model.EvidenceProvenance{SourceType: model.EvidenceSourceScanner, SourceID: sourceID,
			RecordType: "service_observation", RecordID: observation.ID, CollectedAt: collectedAt}}
	if err := insertAssetEvidence(tx, evidence); err != nil {
		return err
	}
	return nil
}

func scannerEvidenceSourceID(tx *sql.Tx, scanID string) (string, error) {
	var workerID string
	err := tx.QueryRow(`SELECT worker_id FROM scanner_worker_jobs WHERE scan_id=? ORDER BY created_at DESC LIMIT 1`, scanID).Scan(&workerID)
	if errors.Is(err, sql.ErrNoRows) {
		return localScannerSourceID, nil
	}
	if err != nil {
		return "", fmt.Errorf("resolve scanner evidence source: %w", err)
	}
	return "scanner-worker/" + workerID, nil
}

func (s *SQLiteStore) AssetDetail(id string, now time.Time) (model.AssetDetail, error) {
	rows, err := s.ListAssets()
	if err != nil {
		return model.AssetDetail{}, err
	}
	var detail model.AssetDetail
	found := false
	for _, asset := range rows {
		if asset.ID == id {
			detail.Asset = asset
			found = true
			break
		}
	}
	if !found {
		return detail, ErrAssetNotFound
	}
	detail.Services, err = s.loadAssetServices(id, now)
	if err != nil {
		return detail, err
	}
	detail.Evidence, err = s.loadAssetEvidence(id)
	return detail, err
}

func (s *SQLiteStore) loadAssetServices(assetID string, now time.Time) ([]model.AssetService, error) {
	rows, err := s.db.Query(`SELECT address,port,protocol,product,version,confidence,state,first_seen,last_seen,last_checked,last_scan_id,observation_count FROM asset_services WHERE asset_id=? ORDER BY state,port,protocol`, assetID)
	if err != nil {
		return nil, err
	}
	services := []model.AssetService{}
	for rows.Next() {
		var item model.AssetService
		var firstSeen, lastSeen, lastChecked string
		if err := rows.Scan(&item.Address, &item.Port, &item.Protocol, &item.Product, &item.Version, &item.Confidence, &item.State, &firstSeen, &lastSeen, &lastChecked, &item.LastScanID, &item.ObservationCount); err != nil {
			_ = rows.Close()
			return nil, err
		}
		item.FirstSeen, _ = parseTime(firstSeen)
		item.LastSeen, _ = parseTime(lastSeen)
		item.LastChecked, _ = parseTime(lastChecked)
		if item.State == model.AssetServiceObserved && now.Sub(item.LastChecked) >= assetServiceStaleAfter {
			item.State = model.AssetServiceStale
		}
		services = append(services, item)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for index := range services {
		services[index].Events, err = s.loadAssetServiceEvents(assetID, services[index])
		if err != nil {
			return nil, err
		}
	}
	return services, nil
}

func (s *SQLiteStore) loadAssetServiceEvents(assetID string, service model.AssetService) ([]model.AssetServiceEvent, error) {
	rows, err := s.db.Query(`SELECT observation_id,scan_id,product,version,confidence,observed_at,finding_ids,cve_ids,source_type,source_id FROM asset_service_events WHERE asset_id=? AND address=? AND port=? AND protocol=? ORDER BY observed_at DESC`, assetID, service.Address, service.Port, service.Protocol)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events := []model.AssetServiceEvent{}
	for rows.Next() {
		var item model.AssetServiceEvent
		var observedAt, findings, cves string
		if err := rows.Scan(&item.ObservationID, &item.ScanID, &item.Product, &item.Version, &item.Confidence, &observedAt, &findings, &cves, &item.Provenance.SourceType, &item.Provenance.SourceID); err != nil {
			return nil, err
		}
		item.ObservedAt, _ = parseTime(observedAt)
		item.Provenance.RecordType = "service_observation"
		item.Provenance.RecordID = item.ObservationID
		item.Provenance.CollectedAt = item.ObservedAt
		_ = json.Unmarshal([]byte(findings), &item.FindingIDs)
		_ = json.Unmarshal([]byte(cves), &item.CVEIDs)
		events = append(events, item)
	}
	return events, rows.Err()
}

func insertAssetEvidence(tx *sql.Tx, evidence model.AssetEvidence) error {
	_, err := tx.Exec(`INSERT INTO asset_evidence(id,asset_id,source_type,source_id,record_type,record_id,scan_id,address,summary,collected_at)VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(source_type,source_id,record_type,record_id)DO NOTHING`, evidence.ID, evidence.AssetID, evidence.SourceType, evidence.SourceID, evidence.RecordType, evidence.RecordID, evidence.ScanID, evidence.Address, evidence.Summary, formatTime(evidence.CollectedAt))
	if err != nil {
		return fmt.Errorf("record asset evidence provenance: %w", err)
	}
	return nil
}

func (s *SQLiteStore) RecordAssetEvidence(evidence model.AssetEvidence) error {
	if err := validateAssetEvidence(evidence); err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := insertAssetEvidence(tx, evidence); err != nil {
		return err
	}
	return tx.Commit()
}

func validateAssetEvidence(evidence model.AssetEvidence) error {
	if evidence.ID == "" || evidence.AssetID == "" || evidence.SourceID == "" || evidence.RecordType == "" || evidence.RecordID == "" || evidence.CollectedAt.IsZero() {
		return errors.New("asset evidence identity and collection time are required")
	}
	if evidence.SourceType != model.EvidenceSourceScanner && evidence.SourceType != model.EvidenceSourceEndpoint {
		return errors.New("asset evidence source type is invalid")
	}
	if len(evidence.ID) > evidenceIdentityLimit || len(evidence.AssetID) > evidenceIdentityLimit || len(evidence.SourceID) > evidenceIdentityLimit || len(evidence.RecordType) > evidenceIdentityLimit || len(evidence.RecordID) > evidenceIdentityLimit || len(evidence.Summary) > evidenceSummaryLimit {
		return errors.New("asset evidence fields exceed their limits")
	}
	return nil
}

func (s *SQLiteStore) loadAssetEvidence(assetID string) ([]model.AssetEvidence, error) {
	rows, err := s.db.Query(`SELECT id,source_type,source_id,record_type,record_id,scan_id,address,summary,collected_at FROM asset_evidence WHERE asset_id=? ORDER BY collected_at DESC`, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []model.AssetEvidence{}
	for rows.Next() {
		var item model.AssetEvidence
		var collectedAt string
		item.AssetID = assetID
		if err := rows.Scan(&item.ID, &item.SourceType, &item.SourceID, &item.RecordType, &item.RecordID, &item.ScanID, &item.Address, &item.Summary, &collectedAt); err != nil {
			return nil, err
		}
		item.CollectedAt, _ = parseTime(collectedAt)
		items = append(items, item)
	}
	return items, rows.Err()
}
