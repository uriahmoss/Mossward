package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"mossward/internal/model"
)

func updatePostgreSQLAssetServiceHistory(tx *sql.Tx, scan model.Scan) error {
	if scan.Status != model.StatusCompleted {
		return nil
	}
	checkedAt := completedOrCreatedAt(scan)
	for _, target := range scan.Targets {
		for _, port := range scan.Ports {
			_, err := tx.Exec(`UPDATE asset_services SET state='not_observed',last_checked=$1,last_scan_id=$2
				WHERE address=$3 AND port=$4 AND last_checked<=$1`, checkedAt, scan.ID, target.Address, port)
			if err != nil {
				return fmt.Errorf("mark PostgreSQL asset service not observed: %w", err)
			}
		}
	}
	sourceID, err := postgreSQLScannerEvidenceSourceID(tx, scan.ID)
	if err != nil {
		return err
	}
	for _, observation := range scan.Observations {
		if err := recordPostgreSQLAssetServiceObservation(tx, scan, observation, checkedAt, sourceID); err != nil {
			return err
		}
	}
	return nil
}

func recordPostgreSQLAssetServiceObservation(
	tx *sql.Tx,
	scan model.Scan,
	observation model.ServiceObservation,
	checkedAt time.Time,
	sourceID string,
) error {
	assetID, err := lookupPostgreSQLAssetID(tx, `SELECT asset_id FROM asset_addresses WHERE address=$1`, observation.Address)
	if err != nil || assetID == "" {
		return err
	}
	findingIDs, cveIDs := postgreSQLObservationRelationshipIDs(scan, observation)
	findingsJSON, err := json.Marshal(findingIDs)
	if err != nil {
		return fmt.Errorf("encode PostgreSQL service-event findings: %w", err)
	}
	cvesJSON, err := json.Marshal(cveIDs)
	if err != nil {
		return fmt.Errorf("encode PostgreSQL service-event CVEs: %w", err)
	}
	collectedAt := observation.ObservedAt
	if collectedAt.IsZero() {
		collectedAt = checkedAt
	}
	result, err := tx.Exec(`INSERT INTO asset_service_events
		(observation_id,asset_id,scan_id,address,port,protocol,product,version,confidence,observed_at,
		 finding_ids,cve_ids,source_type,source_id)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12::jsonb,$13,$14)
		ON CONFLICT(observation_id) DO NOTHING`, observation.ID, assetID, scan.ID, observation.Address, observation.Port,
		observation.Protocol, observation.Product, observation.Version, observation.Confidence, collectedAt,
		string(findingsJSON), string(cvesJSON), model.EvidenceSourceScanner, sourceID)
	if err != nil {
		return fmt.Errorf("record PostgreSQL asset service event: %w", err)
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("count PostgreSQL asset service event: %w", err)
	}
	increment := 0
	if inserted == 1 {
		increment = 1
	}
	_, err = tx.Exec(`INSERT INTO asset_services
		(asset_id,address,port,protocol,product,version,confidence,state,first_seen,last_seen,last_checked,last_scan_id,observation_count)
		VALUES($1,$2,$3,$4,$5,$6,$7,'observed',$8,$8,$9,$10,1)
		ON CONFLICT(asset_id,address,port,protocol) DO UPDATE SET
		product=CASE WHEN EXCLUDED.last_checked>=asset_services.last_checked THEN EXCLUDED.product ELSE asset_services.product END,
		version=CASE WHEN EXCLUDED.last_checked>=asset_services.last_checked THEN EXCLUDED.version ELSE asset_services.version END,
		confidence=CASE WHEN EXCLUDED.last_checked>=asset_services.last_checked THEN EXCLUDED.confidence ELSE asset_services.confidence END,
		state=CASE WHEN EXCLUDED.last_checked>=asset_services.last_checked THEN 'observed' ELSE asset_services.state END,
		last_seen=GREATEST(asset_services.last_seen,EXCLUDED.last_seen),
		last_checked=GREATEST(asset_services.last_checked,EXCLUDED.last_checked),
		last_scan_id=CASE WHEN EXCLUDED.last_checked>=asset_services.last_checked THEN EXCLUDED.last_scan_id ELSE asset_services.last_scan_id END,
		observation_count=asset_services.observation_count+$11`, assetID, observation.Address, observation.Port,
		observation.Protocol, observation.Product, observation.Version, observation.Confidence, collectedAt, checkedAt, scan.ID, increment)
	if err != nil {
		return fmt.Errorf("update PostgreSQL asset service: %w", err)
	}
	evidence := model.AssetEvidence{
		ID:      "scanner:" + observation.ID,
		AssetID: assetID,
		ScanID:  scan.ID,
		Address: observation.Address,
		Summary: fmt.Sprintf("%s service observed on port %d", observation.Protocol, observation.Port),
		EvidenceProvenance: model.EvidenceProvenance{
			SourceType:  model.EvidenceSourceScanner,
			SourceID:    sourceID,
			RecordType:  "service_observation",
			RecordID:    observation.ID,
			CollectedAt: collectedAt,
		},
	}
	return insertPostgreSQLAssetEvidence(tx, evidence)
}

func postgreSQLScannerEvidenceSourceID(tx *sql.Tx, scanID string) (string, error) {
	var workerID string
	err := tx.QueryRow(`SELECT worker_id FROM scanner_worker_jobs WHERE scan_id=$1 ORDER BY created_at DESC LIMIT 1`, scanID).
		Scan(&workerID)
	if errors.Is(err, sql.ErrNoRows) {
		return localScannerSourceID, nil
	}
	if err != nil {
		return "", fmt.Errorf("resolve PostgreSQL scanner evidence source: %w", err)
	}
	return "scanner-worker/" + workerID, nil
}

func postgreSQLObservationRelationshipIDs(scan model.Scan, observation model.ServiceObservation) ([]string, []string) {
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
	return findingIDs, cveIDs
}
