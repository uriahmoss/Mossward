package store

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"mossward/internal/intelligence"
	"mossward/internal/model"
)

func (s *PostgreSQLStore) UpsertCVEs(records []model.CVERecord) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL CVE update: %w", err)
	}
	defer tx.Rollback()
	for _, record := range records {
		if err := upsertPostgreSQLCVE(tx, record); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit PostgreSQL CVE update: %w", err)
	}
	return nil
}

func upsertPostgreSQLCVE(tx *sql.Tx, record model.CVERecord) error {
	_, err := tx.Exec(`INSERT INTO cves(id,description,published_at,modified_at,cvss_score,cvss_vector,severity,known_exploited,source_url)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(id) DO UPDATE SET description=EXCLUDED.description,
		published_at=EXCLUDED.published_at,modified_at=EXCLUDED.modified_at,cvss_score=EXCLUDED.cvss_score,
		cvss_vector=EXCLUDED.cvss_vector,severity=EXCLUDED.severity,known_exploited=EXCLUDED.known_exploited,
		source_url=EXCLUDED.source_url`, record.ID, record.Description, record.PublishedAt, record.ModifiedAt,
		record.CVSSScore, record.CVSSVector, strings.ToLower(record.Severity), record.KnownExploited, record.SourceURL)
	if err != nil {
		return fmt.Errorf("upsert PostgreSQL CVE %s: %w", record.ID, err)
	}
	if _, err := tx.Exec(`DELETE FROM cve_products WHERE cve_id=$1`, record.ID); err != nil {
		return fmt.Errorf("replace PostgreSQL CVE products: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM cve_references WHERE cve_id=$1`, record.ID); err != nil {
		return fmt.Errorf("replace PostgreSQL CVE references: %w", err)
	}
	for ordinal, product := range record.Products {
		_, err := tx.Exec(`INSERT INTO cve_products(cve_id,ordinal,cpe23,part,vendor,product,version,
			version_start_including,version_start_excluding,version_end_including,version_end_excluding,vulnerable)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, record.ID, ordinal, product.CPE23,
			strings.ToLower(product.Part), strings.ToLower(product.Vendor), strings.ToLower(product.Product), product.Version,
			product.VersionStartIncluding, product.VersionStartExcluding, product.VersionEndIncluding,
			product.VersionEndExcluding, product.Vulnerable)
		if err != nil {
			return fmt.Errorf("store PostgreSQL affected product: %w", err)
		}
	}
	for ordinal, reference := range record.References {
		if _, err := tx.Exec(`INSERT INTO cve_references(cve_id,ordinal,url,source) VALUES($1,$2,$3,$4)`,
			record.ID, ordinal, reference.URL, reference.Source); err != nil {
			return fmt.Errorf("store PostgreSQL CVE reference: %w", err)
		}
	}
	return nil
}

func (s *PostgreSQLStore) MatchObservation(observation model.ServiceObservation) ([]model.CVEMatch, error) {
	vendor, product, ok := intelligence.NormalizeProduct(observation.Product)
	if !ok || strings.TrimSpace(observation.Version) == "" {
		return []model.CVEMatch{}, nil
	}
	rows, err := s.db.Query(`SELECT c.id,c.description,c.cvss_score,c.severity,c.known_exploited,c.source_url,
		p.version,p.version_start_including,p.version_start_excluding,p.version_end_including,p.version_end_excluding
		FROM cve_products p JOIN cves c ON c.id=p.cve_id WHERE p.vendor=$1 AND p.product=$2 AND p.vulnerable=TRUE`,
		vendor, product)
	if err != nil {
		return nil, fmt.Errorf("query PostgreSQL CVE candidates: %w", err)
	}
	defer rows.Close()
	matches := []model.CVEMatch{}
	for rows.Next() {
		match, exact, startIn, startEx, endIn, endEx, err := scanPostgreSQLCVECandidate(rows, observation)
		if err != nil {
			return nil, err
		}
		if !intelligence.VersionAffected(observation.Version, exact, startIn, startEx, endIn, endEx) {
			continue
		}
		matches = append(matches, match)
	}
	return matches, rows.Err()
}

func scanPostgreSQLCVECandidate(scanner interface{ Scan(...any) error }, observation model.ServiceObservation) (model.CVEMatch, string, string, string, string, string, error) {
	match := model.CVEMatch{ObservationID: observation.ID, Target: observation.Target, Address: observation.Address,
		Port: observation.Port, Product: observation.Product, Version: observation.Version, Confidence: "high",
		Evidence:  fmt.Sprintf("Observed %s %s matches the affected NVD version range", observation.Product, observation.Version),
		MatchedAt: time.Now().UTC()}
	var exact, startIn, startEx, endIn, endEx string
	err := scanner.Scan(&match.CVEID, &match.Description, &match.CVSSScore, &match.Severity, &match.KnownExploited,
		&match.SourceURL, &exact, &startIn, &startEx, &endIn, &endEx)
	return match, exact, startIn, startEx, endIn, endEx, err
}

func (s *PostgreSQLStore) RecordFeedStart(source string, started time.Time) error {
	_, err := s.db.Exec(`INSERT INTO feed_sync_status(source,status,last_started,records,error) VALUES($1,'running',$2,0,'')
		ON CONFLICT(source) DO UPDATE SET status='running',last_started=EXCLUDED.last_started,error=''`, source, started)
	return err
}

func (s *PostgreSQLStore) RecordFeedResult(source string, completed time.Time, records int, message string) error {
	status := "ready"
	var success any = completed
	if message != "" {
		status = "failed"
		success = nil
	}
	_, err := s.db.Exec(`INSERT INTO feed_sync_status(source,status,last_success,records,error) VALUES($1,$2,$3,$4,$5)
		ON CONFLICT(source) DO UPDATE SET status=EXCLUDED.status,
		last_success=COALESCE(EXCLUDED.last_success,feed_sync_status.last_success),records=EXCLUDED.records,error=EXCLUDED.error`,
		source, status, success, records, message)
	return err
}

func (s *PostgreSQLStore) FeedStatus() (model.FeedStatus, error) {
	status := model.FeedStatus{Source: "NVD", Status: "not_synced"}
	var started, success sql.NullTime
	err := s.db.QueryRow(`SELECT source,status,last_started,last_success,records,error FROM feed_sync_status WHERE source='NVD'`).
		Scan(&status.Source, &status.Status, &started, &success, &status.Records, &status.Error)
	if err != nil && err != sql.ErrNoRows {
		return status, fmt.Errorf("load PostgreSQL feed status: %w", err)
	}
	status.LastStarted = nullablePostgreSQLTime(started)
	status.LastSuccess = nullablePostgreSQLTime(success)
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM cves`).Scan(&status.DatabaseCVEs); err != nil {
		return status, fmt.Errorf("count PostgreSQL CVEs: %w", err)
	}
	return status, nil
}

func (s *PostgreSQLStore) ListCriticalNews(limit int) ([]model.CVENewsItem, error) {
	if limit < 1 {
		limit = 6
	}
	if limit > 25 {
		limit = 25
	}
	rows, err := s.db.Query(`SELECT c.id,c.description,c.published_at,c.cvss_score,c.severity,c.known_exploited,c.source_url,
		CASE WHEN EXISTS(SELECT 1 FROM cve_matches m WHERE m.cve_id=c.id) THEN 'matched' ELSE 'general' END,
		COALESCE((SELECT product || ' ' || version FROM cve_matches m WHERE m.cve_id=c.id LIMIT 1),'')
		FROM cves c WHERE c.severity='critical' OR c.cvss_score>=9.0
		ORDER BY CASE WHEN EXISTS(SELECT 1 FROM cve_matches m WHERE m.cve_id=c.id) THEN 0 ELSE 1 END,
		c.known_exploited DESC,c.published_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("list critical PostgreSQL CVE news: %w", err)
	}
	defer rows.Close()
	items := []model.CVENewsItem{}
	for rows.Next() {
		var item model.CVENewsItem
		if err := rows.Scan(&item.ID, &item.Description, &item.PublishedAt, &item.CVSSScore, &item.Severity,
			&item.KnownExploited, &item.SourceURL, &item.Relevance, &item.Evidence); err != nil {
			return nil, fmt.Errorf("read critical PostgreSQL CVE news: %w", err)
		}
		if item.Relevance == "matched" {
			item.Evidence = "Observed in this environment: " + item.Evidence
		}
		items = append(items, item)
	}
	return items, rows.Err()
}
