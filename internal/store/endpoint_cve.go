package store

import (
	"fmt"
	"strings"
	"time"

	"mossward/internal/intelligence"
	"mossward/internal/model"
)

func (s *SQLiteStore) RefreshEndpointCVEMatches(endpointID string, matchedAt time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM endpoint_cve_matches WHERE endpoint_id=?`, endpointID); err != nil {
		return err
	}
	rows, err := tx.Query(`SELECT name,version,source FROM endpoint_installed_software WHERE endpoint_id=? AND TRIM(version)<>''`, endpointID)
	if err != nil {
		return err
	}
	type software struct{ name, version, source string }
	items := []software{}
	for rows.Next() {
		var item software
		if err := rows.Scan(&item.name, &item.version, &item.source); err != nil {
			rows.Close()
			return err
		}
		items = append(items, item)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, item := range items {
		vendor, product, ok := intelligence.NormalizeProduct(item.name)
		if !ok {
			continue
		}
		candidates, err := tx.Query(`SELECT c.id,p.version,p.version_start_including,p.version_start_excluding,p.version_end_including,p.version_end_excluding
			FROM cve_products p JOIN cves c ON c.id=p.cve_id WHERE p.vendor=? AND p.product=? AND p.vulnerable=1`, vendor, product)
		if err != nil {
			return err
		}
		for candidates.Next() {
			var cveID, exact, startIn, startEx, endIn, endEx string
			if err := candidates.Scan(&cveID, &exact, &startIn, &startEx, &endIn, &endEx); err != nil {
				candidates.Close()
				return err
			}
			identity := strings.Join([]string{cveID, item.name, item.version, item.source}, "\x00")
			if seen[identity] || !intelligence.VersionAffected(item.version, exact, startIn, startEx, endIn, endEx) {
				continue
			}
			seen[identity] = true
			evidence := fmt.Sprintf("Installed %s %s from %s matches an NVD affected range; vendor backports may change actual exposure", item.name, item.version, item.source)
			if _, err := tx.Exec(`INSERT INTO endpoint_cve_matches(endpoint_id,cve_id,product,version,package_source,confidence,evidence,matched_at) VALUES(?,?,?,?,?,'medium',?,?)`,
				endpointID, cveID, item.name, item.version, item.source, evidence, formatTime(matchedAt)); err != nil {
				candidates.Close()
				return err
			}
		}
		if err := candidates.Close(); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *SQLiteStore) EndpointCVEMatches(endpointID string) ([]model.EndpointCVEMatch, error) {
	rows, err := s.db.Query(`SELECT m.endpoint_id,m.cve_id,m.product,m.version,m.package_source,c.severity,c.cvss_score,c.description,m.confidence,m.evidence,c.known_exploited,c.source_url,m.matched_at
		FROM endpoint_cve_matches m JOIN cves c ON c.id=m.cve_id WHERE m.endpoint_id=? ORDER BY c.known_exploited DESC,c.cvss_score DESC,m.cve_id`, endpointID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	matches := []model.EndpointCVEMatch{}
	for rows.Next() {
		var match model.EndpointCVEMatch
		var matchedAt string
		if err := rows.Scan(&match.EndpointID, &match.CVEID, &match.Product, &match.Version, &match.PackageSource, &match.Severity, &match.CVSSScore,
			&match.Description, &match.Confidence, &match.Evidence, &match.KnownExploited, &match.SourceURL, &matchedAt); err != nil {
			return nil, err
		}
		match.MatchedAt, _ = parseTime(matchedAt)
		matches = append(matches, match)
	}
	return matches, rows.Err()
}
