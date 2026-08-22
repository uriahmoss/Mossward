package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"mossward/internal/intelligence"
	"mossward/internal/model"
)

func (s *PostgreSQLStore) RecordEndpointOSInventory(endpointID string, inventory model.EndpointOSInventory, receivedAt time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL endpoint OS inventory: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.Exec(`INSERT INTO endpoint_os_inventory(endpoint_id,family,name,version,build,kernel,architecture,collected_at,received_at)
		SELECT id,$1,$2,$3,$4,$5,$6,$7,$8 FROM endpoints WHERE id=$9 AND status='active'
		ON CONFLICT(endpoint_id) DO UPDATE SET family=EXCLUDED.family,name=EXCLUDED.name,version=EXCLUDED.version,
		build=EXCLUDED.build,kernel=EXCLUDED.kernel,architecture=EXCLUDED.architecture,
		collected_at=EXCLUDED.collected_at,received_at=EXCLUDED.received_at`, inventory.Family, inventory.Name,
		inventory.Version, inventory.Build, inventory.Kernel, inventory.Architecture, inventory.CollectedAt, receivedAt, endpointID)
	if err != nil {
		return fmt.Errorf("record PostgreSQL endpoint OS inventory: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return ErrNotFound
	}
	if _, err := tx.Exec(`DELETE FROM endpoint_os_patches WHERE endpoint_id=$1`, endpointID); err != nil {
		return fmt.Errorf("replace PostgreSQL endpoint patches: %w", err)
	}
	for _, patch := range inventory.Patches {
		if _, err := tx.Exec(`INSERT INTO endpoint_os_patches(endpoint_id,patch_id,description,installed_at)
			VALUES($1,$2,$3,$4)`, endpointID, patch.ID, patch.Description, patch.InstalledAt); err != nil {
			return fmt.Errorf("record PostgreSQL endpoint patch: %w", err)
		}
	}
	return tx.Commit()
}

func (s *PostgreSQLStore) EndpointOSInventory(endpointID string) (model.EndpointOSInventory, error) {
	var inventory model.EndpointOSInventory
	err := s.db.QueryRow(`SELECT endpoint_id,family,name,version,build,kernel,architecture,collected_at,received_at
		FROM endpoint_os_inventory WHERE endpoint_id=$1`, endpointID).Scan(&inventory.EndpointID, &inventory.Family,
		&inventory.Name, &inventory.Version, &inventory.Build, &inventory.Kernel, &inventory.Architecture,
		&inventory.CollectedAt, &inventory.ReceivedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return inventory, ErrNotFound
	}
	if err != nil {
		return inventory, fmt.Errorf("load PostgreSQL endpoint OS inventory: %w", err)
	}
	rows, err := s.db.Query(`SELECT patch_id,description,installed_at FROM endpoint_os_patches
		WHERE endpoint_id=$1 ORDER BY patch_id`, endpointID)
	if err != nil {
		return inventory, fmt.Errorf("load PostgreSQL endpoint patches: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var patch model.EndpointPatch
		var installedAt sql.NullTime
		if err := rows.Scan(&patch.ID, &patch.Description, &installedAt); err != nil {
			return inventory, fmt.Errorf("read PostgreSQL endpoint patch: %w", err)
		}
		patch.InstalledAt = nullablePostgreSQLTime(installedAt)
		inventory.Patches = append(inventory.Patches, patch)
	}
	return inventory, rows.Err()
}

func (s *PostgreSQLStore) RecordEndpointSoftwareInventory(endpointID string, inventory model.EndpointSoftwareInventory, receivedAt time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL endpoint software inventory: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.Exec(`INSERT INTO endpoint_software_inventory(endpoint_id,collected_at,received_at)
		SELECT id,$1,$2 FROM endpoints WHERE id=$3 AND status='active'
		ON CONFLICT(endpoint_id) DO UPDATE SET collected_at=EXCLUDED.collected_at,received_at=EXCLUDED.received_at`,
		inventory.CollectedAt, receivedAt, endpointID)
	if err != nil {
		return fmt.Errorf("record PostgreSQL endpoint software inventory: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return ErrNotFound
	}
	if _, err := tx.Exec(`DELETE FROM endpoint_installed_software WHERE endpoint_id=$1`, endpointID); err != nil {
		return fmt.Errorf("replace PostgreSQL installed software: %w", err)
	}
	for ordinal, software := range inventory.Items {
		_, err := tx.Exec(`INSERT INTO endpoint_installed_software(endpoint_id,ordinal,name,version,publisher,architecture,source)
			VALUES($1,$2,$3,$4,$5,$6,$7)`, endpointID, ordinal, software.Name, software.Version,
			software.Publisher, software.Architecture, software.Source)
		if err != nil {
			return fmt.Errorf("record PostgreSQL installed software: %w", err)
		}
	}
	if err := refreshPostgreSQLEndpointCVEMatches(tx, endpointID, receivedAt); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgreSQLStore) EndpointSoftwareInventory(endpointID string) (model.EndpointSoftwareInventory, error) {
	var inventory model.EndpointSoftwareInventory
	err := s.db.QueryRow(`SELECT endpoint_id,collected_at,received_at FROM endpoint_software_inventory WHERE endpoint_id=$1`, endpointID).
		Scan(&inventory.EndpointID, &inventory.CollectedAt, &inventory.ReceivedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return inventory, ErrNotFound
	}
	if err != nil {
		return inventory, fmt.Errorf("load PostgreSQL endpoint software inventory: %w", err)
	}
	rows, err := s.db.Query(`SELECT name,version,publisher,architecture,source FROM endpoint_installed_software
		WHERE endpoint_id=$1 ORDER BY ordinal`, endpointID)
	if err != nil {
		return inventory, fmt.Errorf("load PostgreSQL installed software: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var software model.InstalledSoftware
		if err := rows.Scan(&software.Name, &software.Version, &software.Publisher, &software.Architecture, &software.Source); err != nil {
			return inventory, fmt.Errorf("read PostgreSQL installed software: %w", err)
		}
		inventory.Items = append(inventory.Items, software)
	}
	return inventory, rows.Err()
}

func (s *PostgreSQLStore) RefreshEndpointCVEMatches(endpointID string, matchedAt time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL endpoint CVE refresh: %w", err)
	}
	defer tx.Rollback()
	if err := refreshPostgreSQLEndpointCVEMatches(tx, endpointID, matchedAt); err != nil {
		return err
	}
	return tx.Commit()
}

func refreshPostgreSQLEndpointCVEMatches(tx *sql.Tx, endpointID string, matchedAt time.Time) error {
	if _, err := tx.Exec(`DELETE FROM endpoint_cve_matches WHERE endpoint_id=$1`, endpointID); err != nil {
		return fmt.Errorf("replace PostgreSQL endpoint CVE matches: %w", err)
	}
	rows, err := tx.Query(`SELECT name,version,source FROM endpoint_installed_software
		WHERE endpoint_id=$1 AND BTRIM(version)<>''`, endpointID)
	if err != nil {
		return fmt.Errorf("load PostgreSQL software for CVE matching: %w", err)
	}
	type softwareRecord struct{ name, version, source string }
	software := []softwareRecord{}
	for rows.Next() {
		var item softwareRecord
		if err := rows.Scan(&item.name, &item.version, &item.source); err != nil {
			_ = rows.Close()
			return err
		}
		software = append(software, item)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, item := range software {
		if err := matchPostgreSQLEndpointSoftware(tx, endpointID, item.name, item.version, item.source, matchedAt, seen); err != nil {
			return err
		}
	}
	return nil
}

func matchPostgreSQLEndpointSoftware(tx *sql.Tx, endpointID, name, version, source string, matchedAt time.Time, seen map[string]bool) error {
	vendor, product, ok := intelligence.NormalizeProduct(name)
	if !ok {
		return nil
	}
	rows, err := tx.Query(`SELECT c.id,p.version,p.version_start_including,p.version_start_excluding,
		p.version_end_including,p.version_end_excluding FROM cve_products p JOIN cves c ON c.id=p.cve_id
		WHERE p.vendor=$1 AND p.product=$2 AND p.vulnerable=TRUE`, vendor, product)
	if err != nil {
		return fmt.Errorf("query PostgreSQL endpoint CVE candidates: %w", err)
	}
	type cveCandidate struct{ id, exact, startIn, startEx, endIn, endEx string }
	candidates := []cveCandidate{}
	for rows.Next() {
		var candidate cveCandidate
		if err := rows.Scan(&candidate.id, &candidate.exact, &candidate.startIn, &candidate.startEx,
			&candidate.endIn, &candidate.endEx); err != nil {
			_ = rows.Close()
			return err
		}
		candidates = append(candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, candidate := range candidates {
		identity := strings.Join([]string{candidate.id, name, version, source}, "\x00")
		if seen[identity] || !intelligence.VersionAffected(version, candidate.exact, candidate.startIn,
			candidate.startEx, candidate.endIn, candidate.endEx) {
			continue
		}
		seen[identity] = true
		evidence := fmt.Sprintf("Installed %s %s from %s matches an NVD affected range; vendor backports may change actual exposure", name, version, source)
		_, err := tx.Exec(`INSERT INTO endpoint_cve_matches(endpoint_id,cve_id,product,version,package_source,confidence,evidence,matched_at)
			VALUES($1,$2,$3,$4,$5,'medium',$6,$7)`, endpointID, candidate.id, name, version, source, evidence, matchedAt)
		if err != nil {
			return fmt.Errorf("record PostgreSQL endpoint CVE match: %w", err)
		}
	}
	return nil
}

func (s *PostgreSQLStore) EndpointCVEMatches(endpointID string) ([]model.EndpointCVEMatch, error) {
	rows, err := s.db.Query(`SELECT m.endpoint_id,m.cve_id,m.product,m.version,m.package_source,c.severity,c.cvss_score,
		c.description,m.confidence,m.evidence,c.known_exploited,c.source_url,m.matched_at
		FROM endpoint_cve_matches m JOIN cves c ON c.id=m.cve_id WHERE m.endpoint_id=$1
		ORDER BY c.known_exploited DESC,c.cvss_score DESC,m.cve_id`, endpointID)
	if err != nil {
		return nil, fmt.Errorf("load PostgreSQL endpoint CVE matches: %w", err)
	}
	defer rows.Close()
	matches := []model.EndpointCVEMatch{}
	for rows.Next() {
		var match model.EndpointCVEMatch
		if err := rows.Scan(&match.EndpointID, &match.CVEID, &match.Product, &match.Version, &match.PackageSource,
			&match.Severity, &match.CVSSScore, &match.Description, &match.Confidence, &match.Evidence,
			&match.KnownExploited, &match.SourceURL, &match.MatchedAt); err != nil {
			return nil, fmt.Errorf("read PostgreSQL endpoint CVE match: %w", err)
		}
		matches = append(matches, match)
	}
	return matches, rows.Err()
}
