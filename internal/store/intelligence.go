package store

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"mossward/internal/intelligence"
	"mossward/internal/model"
)

func (s *SQLiteStore) UpsertCVEs(records []model.CVERecord) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin CVE update: %w", err)
	}
	defer tx.Rollback()
	for _, record := range records {
		if _, err := tx.Exec(`INSERT INTO cves(id, description, published_at, modified_at, cvss_score, cvss_vector, severity, known_exploited, source_url)
			VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(id) DO UPDATE SET description=excluded.description, published_at=excluded.published_at,
			modified_at=excluded.modified_at, cvss_score=excluded.cvss_score, cvss_vector=excluded.cvss_vector,
			severity=excluded.severity, known_exploited=excluded.known_exploited, source_url=excluded.source_url`,
			record.ID, record.Description, formatTime(record.PublishedAt), formatTime(record.ModifiedAt),
			record.CVSSScore, record.CVSSVector, strings.ToLower(record.Severity), record.KnownExploited, record.SourceURL); err != nil {
			return fmt.Errorf("upsert CVE %s: %w", record.ID, err)
		}
		if _, err := tx.Exec(`DELETE FROM cve_products WHERE cve_id = ?`, record.ID); err != nil {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM cve_references WHERE cve_id = ?`, record.ID); err != nil {
			return err
		}
		for index, product := range record.Products {
			if _, err := tx.Exec(`INSERT INTO cve_products(cve_id, ordinal, cpe23, part, vendor, product, version,
				version_start_including, version_start_excluding, version_end_including, version_end_excluding, vulnerable)
				VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, record.ID, index, product.CPE23,
				strings.ToLower(product.Part), strings.ToLower(product.Vendor), strings.ToLower(product.Product), product.Version,
				product.VersionStartIncluding, product.VersionStartExcluding, product.VersionEndIncluding,
				product.VersionEndExcluding, product.Vulnerable); err != nil {
				return fmt.Errorf("store affected product: %w", err)
			}
		}
		for index, reference := range record.References {
			if _, err := tx.Exec(`INSERT INTO cve_references(cve_id, ordinal, url, source) VALUES(?, ?, ?, ?)`,
				record.ID, index, reference.URL, reference.Source); err != nil {
				return fmt.Errorf("store CVE reference: %w", err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit CVE update: %w", err)
	}
	return s.refreshAllEndpointCVEMatches(time.Now().UTC())
}

func (s *SQLiteStore) refreshAllEndpointCVEMatches(at time.Time) error {
	rows, err := s.db.Query(`SELECT endpoint_id FROM endpoint_software_inventory`)
	if err != nil {
		return err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, id := range ids {
		if err := s.RefreshEndpointCVEMatches(id, at); err != nil {
			return err
		}
	}
	return nil
}

func (s *SQLiteStore) MatchObservation(observation model.ServiceObservation) ([]model.CVEMatch, error) {
	vendor, product, ok := intelligence.NormalizeProduct(observation.Product)
	if !ok || strings.TrimSpace(observation.Version) == "" {
		return []model.CVEMatch{}, nil
	}
	rows, err := s.db.Query(`SELECT c.id, c.description, c.cvss_score, c.severity, c.known_exploited, c.source_url,
		p.version, p.version_start_including, p.version_start_excluding, p.version_end_including, p.version_end_excluding
		FROM cve_products p JOIN cves c ON c.id = p.cve_id
		WHERE p.vendor = ? AND p.product = ? AND p.vulnerable = 1`, vendor, product)
	if err != nil {
		return nil, fmt.Errorf("query CVE candidates: %w", err)
	}
	defer rows.Close()
	var matches []model.CVEMatch
	for rows.Next() {
		var id, description, severity, sourceURL, exact, startIn, startEx, endIn, endEx string
		var score float64
		var exploited bool
		if err := rows.Scan(&id, &description, &score, &severity, &exploited, &sourceURL, &exact, &startIn, &startEx, &endIn, &endEx); err != nil {
			return nil, err
		}
		if !intelligence.VersionAffected(observation.Version, exact, startIn, startEx, endIn, endEx) {
			continue
		}
		matches = append(matches, model.CVEMatch{
			CVEID: id, ObservationID: observation.ID, Target: observation.Target, Address: observation.Address,
			Port: observation.Port, Product: observation.Product, Version: observation.Version,
			Severity: severity, CVSSScore: score, Description: description, Confidence: "high",
			Evidence:       fmt.Sprintf("Observed %s %s matches the affected NVD version range", observation.Product, observation.Version),
			KnownExploited: exploited, SourceURL: sourceURL, MatchedAt: time.Now().UTC(),
		})
	}
	return matches, rows.Err()
}

func (s *SQLiteStore) ListCriticalNews(limit int) ([]model.CVENewsItem, error) {
	if limit < 1 {
		limit = 6
	}
	if limit > 25 {
		limit = 25
	}
	rows, err := s.db.Query(`SELECT c.id, c.description, c.published_at, c.cvss_score, c.severity,
		c.known_exploited, c.source_url,
		CASE WHEN EXISTS(SELECT 1 FROM cve_matches m WHERE m.cve_id=c.id) OR EXISTS(SELECT 1 FROM endpoint_cve_matches em WHERE em.cve_id=c.id) THEN 'matched' ELSE 'general' END,
		COALESCE((SELECT product || ' ' || version FROM cve_matches m WHERE m.cve_id=c.id LIMIT 1),
			(SELECT product || ' ' || version FROM endpoint_cve_matches em WHERE em.cve_id=c.id LIMIT 1), '')
		FROM cves c WHERE c.severity = 'critical' OR c.cvss_score >= 9.0
		ORDER BY CASE WHEN EXISTS(SELECT 1 FROM cve_matches m WHERE m.cve_id=c.id) OR EXISTS(SELECT 1 FROM endpoint_cve_matches em WHERE em.cve_id=c.id) THEN 0 ELSE 1 END,
			c.known_exploited DESC, c.published_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list critical CVE news: %w", err)
	}
	defer rows.Close()
	items := []model.CVENewsItem{}
	for rows.Next() {
		var item model.CVENewsItem
		var published string
		if err := rows.Scan(&item.ID, &item.Description, &published, &item.CVSSScore, &item.Severity,
			&item.KnownExploited, &item.SourceURL, &item.Relevance, &item.Evidence); err != nil {
			return nil, err
		}
		if item.PublishedAt, err = parseTime(published); err != nil {
			return nil, err
		}
		if item.Relevance == "matched" {
			item.Evidence = "Observed in this environment: " + item.Evidence
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *SQLiteStore) RecordFeedStart(source string, started time.Time) error {
	_, err := s.db.Exec(`INSERT INTO feed_sync_status(source, status, last_started, records, error) VALUES(?, 'running', ?, 0, '')
		ON CONFLICT(source) DO UPDATE SET status='running', last_started=excluded.last_started, error=''`, source, formatTime(started))
	return err
}

func (s *SQLiteStore) RecordFeedResult(source string, completed time.Time, records int, message string) error {
	status := "ready"
	var success any = formatTime(completed)
	if message != "" {
		status = "failed"
		success = nil
	}
	_, err := s.db.Exec(`INSERT INTO feed_sync_status(source, status, last_success, records, error) VALUES(?, ?, ?, ?, ?)
		ON CONFLICT(source) DO UPDATE SET status=excluded.status,
		last_success=COALESCE(excluded.last_success, feed_sync_status.last_success), records=excluded.records, error=excluded.error`,
		source, status, success, records, message)
	return err
}

func (s *SQLiteStore) FeedStatus() (model.FeedStatus, error) {
	status := model.FeedStatus{Source: "NVD", Status: "not_synced"}
	var started, success sql.NullString
	err := s.db.QueryRow(`SELECT source, status, last_started, last_success, records, error FROM feed_sync_status WHERE source='NVD'`).
		Scan(&status.Source, &status.Status, &started, &success, &status.Records, &status.Error)
	if err != nil && err != sql.ErrNoRows {
		return status, err
	}
	if started.Valid {
		status.LastStarted, err = parseOptionalTime(started)
		if err != nil {
			return status, err
		}
	}
	if success.Valid {
		status.LastSuccess, err = parseOptionalTime(success)
		if err != nil {
			return status, err
		}
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM cves`).Scan(&status.DatabaseCVEs); err != nil {
		return status, err
	}
	return status, nil
}

func (s *SQLiteStore) loadCVEMatches(scan *model.Scan) error {
	rows, err := s.db.Query(`SELECT m.cve_id, m.observation_id, m.target, m.address, m.port, m.product, m.version,
		c.severity, c.cvss_score, c.description, m.confidence, m.evidence, c.known_exploited, c.source_url, m.matched_at
		FROM cve_matches m JOIN cves c ON c.id=m.cve_id WHERE m.scan_id=? ORDER BY m.ordinal`, scan.ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	scan.CVEMatches = []model.CVEMatch{}
	for rows.Next() {
		var match model.CVEMatch
		var matched string
		if err := rows.Scan(&match.CVEID, &match.ObservationID, &match.Target, &match.Address, &match.Port,
			&match.Product, &match.Version, &match.Severity, &match.CVSSScore, &match.Description,
			&match.Confidence, &match.Evidence, &match.KnownExploited, &match.SourceURL, &matched); err != nil {
			return err
		}
		if match.MatchedAt, err = parseTime(matched); err != nil {
			return err
		}
		scan.CVEMatches = append(scan.CVEMatches, match)
	}
	return rows.Err()
}
