package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"mossward/internal/model"
)

func (s *PostgreSQLStore) Save(scan model.Scan) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL scan save: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM scans WHERE id=$1`, scan.ID); err != nil {
		return fmt.Errorf("replace PostgreSQL scan: %w", err)
	}
	_, err = tx.Exec(`INSERT INTO scans(id,name,status,error,total_checks,done_checks,created_at,started_at,completed_at,
		scope_policy_id,max_concurrent,scan_policy_id,active_seconds,window_end,long_alert_sent,rate_limit_per_second)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`, scan.ID, scan.Name, scan.Status,
		scan.Error, scan.TotalChecks, scan.DoneChecks, scan.CreatedAt, scan.StartedAt, scan.CompletedAt, scan.ScopePolicyID,
		scan.MaxConcurrent, scan.ScanPolicyID, scan.ActiveSeconds, scan.WindowEnd, scan.LongAlertSent, scan.RateLimitPerSecond)
	if err != nil {
		return fmt.Errorf("insert PostgreSQL scan: %w", err)
	}
	if err := savePostgreSQLScanChildren(tx, scan); err != nil {
		return err
	}
	return tx.Commit()
}

func savePostgreSQLScanChildren(tx *sql.Tx, scan model.Scan) error {
	for ordinal, target := range scan.Targets {
		groupIDs, err := json.Marshal(target.GroupIDs)
		if err != nil {
			return fmt.Errorf("encode PostgreSQL scan target groups: %w", err)
		}
		if _, err := tx.Exec(`INSERT INTO scan_targets(scan_id,ordinal,name,address,group_ids) VALUES($1,$2,$3,$4,$5::jsonb)`,
			scan.ID, ordinal, target.Name, target.Address, string(groupIDs)); err != nil {
			return fmt.Errorf("insert PostgreSQL scan target: %w", err)
		}
	}
	for ordinal, port := range scan.Ports {
		if _, err := tx.Exec(`INSERT INTO scan_ports(scan_id,ordinal,port) VALUES($1,$2,$3)`, scan.ID, ordinal, port); err != nil {
			return fmt.Errorf("insert PostgreSQL scan port: %w", err)
		}
	}
	if err := savePostgreSQLObservations(tx, scan); err != nil {
		return err
	}
	if err := savePostgreSQLFindings(tx, scan); err != nil {
		return err
	}
	for ordinal, match := range scan.CVEMatches {
		_, err := tx.Exec(`INSERT INTO cve_matches(scan_id,observation_id,cve_id,ordinal,target,address,port,product,
			version,confidence,evidence,matched_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, scan.ID,
			match.ObservationID, match.CVEID, ordinal, match.Target, match.Address, match.Port, match.Product,
			match.Version, match.Confidence, match.Evidence, match.MatchedAt)
		if err != nil {
			return fmt.Errorf("insert PostgreSQL CVE match: %w", err)
		}
	}
	for _, checkpoint := range scan.Checkpoints {
		if _, err := tx.Exec(`INSERT INTO scan_checkpoints(scan_id,address,port,completed_at) VALUES($1,$2,$3,$4)`,
			scan.ID, checkpoint.Address, checkpoint.Port, checkpoint.CompletedAt); err != nil {
			return fmt.Errorf("insert PostgreSQL scan checkpoint: %w", err)
		}
	}
	return nil
}

func savePostgreSQLObservations(tx *sql.Tx, scan model.Scan) error {
	for ordinal, observation := range scan.Observations {
		_, err := tx.Exec(`INSERT INTO service_observations(id,scan_id,ordinal,target,address,port,protocol,product,version,
			confidence,evidence,observed_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, observation.ID,
			scan.ID, ordinal, observation.Target, observation.Address, observation.Port, observation.Protocol,
			observation.Product, observation.Version, observation.Confidence, observation.Evidence, observation.ObservedAt)
		if err != nil {
			return fmt.Errorf("insert PostgreSQL service observation: %w", err)
		}
		for key, value := range observation.Metadata {
			if _, err := tx.Exec(`INSERT INTO observation_metadata(observation_id,key,value) VALUES($1,$2,$3)`,
				observation.ID, key, value); err != nil {
				return fmt.Errorf("insert PostgreSQL observation metadata: %w", err)
			}
		}
	}
	return nil
}

func savePostgreSQLFindings(tx *sql.Tx, scan model.Scan) error {
	for ordinal, finding := range scan.Findings {
		_, err := tx.Exec(`INSERT INTO findings(id,scan_id,ordinal,check_id,target,address,port,service,severity,title,
			evidence,remediation,observed_at,status,assigned_to,workflow_updated_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,NULLIF($15,''),$16)`, finding.ID, scan.ID,
			ordinal, finding.CheckID, finding.Target, finding.Address, finding.Port, finding.Service, finding.Severity,
			finding.Title, finding.Evidence, finding.Remediation, finding.ObservedAt, defaultFindingStatus(finding.Status),
			finding.AssignedTo, finding.WorkflowUpdatedAt)
		if err != nil {
			return fmt.Errorf("insert PostgreSQL finding: %w", err)
		}
	}
	return nil
}

func (s *PostgreSQLStore) Get(id string) (model.Scan, error) {
	var scan model.Scan
	var started, completed, windowEnd sql.NullTime
	err := s.db.QueryRow(`SELECT id,name,status,error,total_checks,done_checks,created_at,started_at,completed_at,
		scope_policy_id,max_concurrent,scan_policy_id,active_seconds,window_end,long_alert_sent,rate_limit_per_second
		FROM scans WHERE id=$1`, id).Scan(&scan.ID, &scan.Name, &scan.Status, &scan.Error, &scan.TotalChecks,
		&scan.DoneChecks, &scan.CreatedAt, &started, &completed, &scan.ScopePolicyID, &scan.MaxConcurrent,
		&scan.ScanPolicyID, &scan.ActiveSeconds, &windowEnd, &scan.LongAlertSent, &scan.RateLimitPerSecond)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Scan{}, ErrNotFound
	}
	if err != nil {
		return model.Scan{}, fmt.Errorf("get PostgreSQL scan: %w", err)
	}
	scan.StartedAt = nullablePostgreSQLTime(started)
	scan.CompletedAt = nullablePostgreSQLTime(completed)
	scan.WindowEnd = nullablePostgreSQLTime(windowEnd)
	loaders := []func(*model.Scan) error{s.loadPostgreSQLTargets, s.loadPostgreSQLPorts, s.loadPostgreSQLObservations,
		s.loadPostgreSQLFindings, s.loadPostgreSQLCVEMatches, s.loadPostgreSQLCheckpoints}
	for _, load := range loaders {
		if err := load(&scan); err != nil {
			return model.Scan{}, err
		}
	}
	var alertCount int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM scan_long_alerts WHERE scan_id=$1`, scan.ID).Scan(&alertCount); err != nil {
		return model.Scan{}, fmt.Errorf("load PostgreSQL scan alert state: %w", err)
	}
	scan.LongAlertSent = alertCount > 0
	return scan, nil
}

func nullablePostgreSQLTime(value sql.NullTime) *time.Time {
	if !value.Valid {
		return nil
	}
	return &value.Time
}

func (s *PostgreSQLStore) List() ([]model.Scan, error) {
	rows, err := s.db.Query(`SELECT id FROM scans ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list PostgreSQL scan IDs: %w", err)
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("read PostgreSQL scan ID: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close PostgreSQL scan ID query: %w", err)
	}
	scans := make([]model.Scan, 0, len(ids))
	for _, id := range ids {
		scan, err := s.Get(id)
		if err != nil {
			return nil, err
		}
		scans = append(scans, scan)
	}
	return scans, nil
}

func (s *PostgreSQLStore) ReconcileInterrupted() error {
	_, err := s.db.Exec(`UPDATE scans SET
		status=CASE WHEN scan_policy_id<>'' THEN $1 ELSE $2 END,
		error=CASE WHEN scan_policy_id<>'' THEN 'scheduled scan paused by process shutdown' ELSE 'scan interrupted by a previous process shutdown' END,
		completed_at=CASE WHEN scan_policy_id<>'' THEN NULL ELSE $3 END,
		active_seconds=active_seconds+CASE WHEN scan_policy_id<>'' AND status=$4 AND started_at IS NOT NULL
			THEN GREATEST(0,EXTRACT(EPOCH FROM ($3-started_at))::BIGINT) ELSE 0 END,
		started_at=CASE WHEN scan_policy_id<>'' THEN NULL ELSE started_at END
		WHERE status IN ($5,$6)`, model.StatusPaused, model.StatusFailed, time.Now().UTC(), model.StatusRunning,
		model.StatusQueued, model.StatusRunning)
	if err != nil {
		return fmt.Errorf("reconcile interrupted PostgreSQL scans: %w", err)
	}
	return nil
}

func (s *PostgreSQLStore) loadPostgreSQLTargets(scan *model.Scan) error {
	rows, err := s.db.Query(`SELECT name,address,group_ids FROM scan_targets WHERE scan_id=$1 ORDER BY ordinal`, scan.ID)
	if err != nil {
		return fmt.Errorf("load PostgreSQL scan targets: %w", err)
	}
	defer rows.Close()
	scan.Targets = []model.Target{}
	for rows.Next() {
		var target model.Target
		var groupIDs []byte
		if err := rows.Scan(&target.Name, &target.Address, &groupIDs); err != nil {
			return fmt.Errorf("read PostgreSQL scan target: %w", err)
		}
		if err := json.Unmarshal(groupIDs, &target.GroupIDs); err != nil {
			return fmt.Errorf("decode PostgreSQL scan target groups: %w", err)
		}
		scan.Targets = append(scan.Targets, target)
	}
	return rows.Err()
}

func (s *PostgreSQLStore) loadPostgreSQLPorts(scan *model.Scan) error {
	rows, err := s.db.Query(`SELECT port FROM scan_ports WHERE scan_id=$1 ORDER BY ordinal`, scan.ID)
	if err != nil {
		return fmt.Errorf("load PostgreSQL scan ports: %w", err)
	}
	defer rows.Close()
	scan.Ports = []int{}
	for rows.Next() {
		var port int
		if err := rows.Scan(&port); err != nil {
			return fmt.Errorf("read PostgreSQL scan port: %w", err)
		}
		scan.Ports = append(scan.Ports, port)
	}
	return rows.Err()
}

func (s *PostgreSQLStore) loadPostgreSQLObservations(scan *model.Scan) error {
	rows, err := s.db.Query(`SELECT id,target,address,port,protocol,product,version,confidence,evidence,observed_at
		FROM service_observations WHERE scan_id=$1 ORDER BY ordinal`, scan.ID)
	if err != nil {
		return fmt.Errorf("load PostgreSQL service observations: %w", err)
	}
	scan.Observations = []model.ServiceObservation{}
	for rows.Next() {
		var observation model.ServiceObservation
		if err := rows.Scan(&observation.ID, &observation.Target, &observation.Address, &observation.Port,
			&observation.Protocol, &observation.Product, &observation.Version, &observation.Confidence,
			&observation.Evidence, &observation.ObservedAt); err != nil {
			_ = rows.Close()
			return fmt.Errorf("read PostgreSQL service observation: %w", err)
		}
		scan.Observations = append(scan.Observations, observation)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for index := range scan.Observations {
		if err := s.loadPostgreSQLObservationMetadata(&scan.Observations[index]); err != nil {
			return err
		}
	}
	return nil
}

func (s *PostgreSQLStore) loadPostgreSQLObservationMetadata(observation *model.ServiceObservation) error {
	rows, err := s.db.Query(`SELECT key,value FROM observation_metadata WHERE observation_id=$1 ORDER BY key`, observation.ID)
	if err != nil {
		return fmt.Errorf("load PostgreSQL observation metadata: %w", err)
	}
	defer rows.Close()
	metadata := map[string]string{}
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return fmt.Errorf("read PostgreSQL observation metadata: %w", err)
		}
		metadata[key] = value
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(metadata) > 0 {
		observation.Metadata = metadata
	}
	return nil
}

func (s *PostgreSQLStore) loadPostgreSQLFindings(scan *model.Scan) error {
	rows, err := s.db.Query(`SELECT id,check_id,target,address,port,service,severity,title,evidence,remediation,
		observed_at,status,COALESCE(assigned_to,''),workflow_updated_at FROM findings WHERE scan_id=$1 ORDER BY ordinal`, scan.ID)
	if err != nil {
		return fmt.Errorf("load PostgreSQL findings: %w", err)
	}
	defer rows.Close()
	scan.Findings = []model.Finding{}
	for rows.Next() {
		var finding model.Finding
		var workflowUpdated sql.NullTime
		if err := rows.Scan(&finding.ID, &finding.CheckID, &finding.Target, &finding.Address, &finding.Port,
			&finding.Service, &finding.Severity, &finding.Title, &finding.Evidence, &finding.Remediation,
			&finding.ObservedAt, &finding.Status, &finding.AssignedTo, &workflowUpdated); err != nil {
			return fmt.Errorf("read PostgreSQL finding: %w", err)
		}
		finding.WorkflowUpdatedAt = nullablePostgreSQLTime(workflowUpdated)
		scan.Findings = append(scan.Findings, finding)
	}
	return rows.Err()
}

func (s *PostgreSQLStore) loadPostgreSQLCheckpoints(scan *model.Scan) error {
	rows, err := s.db.Query(`SELECT address,port,completed_at FROM scan_checkpoints WHERE scan_id=$1 ORDER BY address,port`, scan.ID)
	if err != nil {
		return fmt.Errorf("load PostgreSQL scan checkpoints: %w", err)
	}
	defer rows.Close()
	scan.Checkpoints = []model.ScanCheckpoint{}
	for rows.Next() {
		var checkpoint model.ScanCheckpoint
		if err := rows.Scan(&checkpoint.Address, &checkpoint.Port, &checkpoint.CompletedAt); err != nil {
			return fmt.Errorf("read PostgreSQL scan checkpoint: %w", err)
		}
		scan.Checkpoints = append(scan.Checkpoints, checkpoint)
	}
	return rows.Err()
}

func (s *PostgreSQLStore) loadPostgreSQLCVEMatches(scan *model.Scan) error {
	rows, err := s.db.Query(`SELECT m.cve_id,m.observation_id,m.target,m.address,m.port,m.product,m.version,
		c.severity,c.cvss_score,c.description,m.confidence,m.evidence,c.known_exploited,c.source_url,m.matched_at
		FROM cve_matches m JOIN cves c ON c.id=m.cve_id WHERE m.scan_id=$1 ORDER BY m.ordinal`, scan.ID)
	if err != nil {
		return fmt.Errorf("load PostgreSQL CVE matches: %w", err)
	}
	defer rows.Close()
	scan.CVEMatches = []model.CVEMatch{}
	for rows.Next() {
		var match model.CVEMatch
		if err := rows.Scan(&match.CVEID, &match.ObservationID, &match.Target, &match.Address, &match.Port,
			&match.Product, &match.Version, &match.Severity, &match.CVSSScore, &match.Description, &match.Confidence,
			&match.Evidence, &match.KnownExploited, &match.SourceURL, &match.MatchedAt); err != nil {
			return fmt.Errorf("read PostgreSQL CVE match: %w", err)
		}
		scan.CVEMatches = append(scan.CVEMatches, match)
	}
	return rows.Err()
}
