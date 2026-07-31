package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"mossward/internal/model"

	_ "modernc.org/sqlite"
)

const schemaVersion = 1

type SQLiteStore struct {
	db *sql.DB
}

func NewSQLiteStore(path, legacyJSONPath string) (*SQLiteStore, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("create database directory: %w", err)
	}
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve database path: %w", err)
	}
	slashPath := filepath.ToSlash(absolutePath)
	if filepath.VolumeName(absolutePath) != "" && !strings.HasPrefix(slashPath, "/") {
		slashPath = "/" + slashPath
	}
	dsn := (&url.URL{
		Scheme:   "file",
		Path:     slashPath,
		RawQuery: "_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)",
	}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open SQLite database: %w", err)
	}
	db.SetMaxOpenConns(1)
	store := &SQLiteStore{db: db}
	if err := store.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("secure database permissions: %w", err)
	}
	if err := store.importLegacyJSON(legacyJSONPath); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

func (s *SQLiteStore) migrate() error {
	if _, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			applied_at TEXT NOT NULL
		)
	`); err != nil {
		return fmt.Errorf("create migration table: %w", err)
	}
	var current int
	if err := s.db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&current); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if current > schemaVersion {
		return fmt.Errorf("database schema version %d is newer than supported version %d", current, schemaVersion)
	}
	if current < 1 {
		if err := s.applyMigrationOne(); err != nil {
			return err
		}
	}
	return nil
}

func (s *SQLiteStore) applyMigrationOne() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin schema migration: %w", err)
	}
	defer tx.Rollback()
	statements := []string{
		`CREATE TABLE scans (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			status TEXT NOT NULL,
			error TEXT NOT NULL DEFAULT '',
			total_checks INTEGER NOT NULL DEFAULT 0,
			done_checks INTEGER NOT NULL DEFAULT 0,
			created_at TEXT NOT NULL,
			started_at TEXT,
			completed_at TEXT
		)`,
		`CREATE INDEX scans_created_at_idx ON scans(created_at DESC)`,
		`CREATE TABLE scan_targets (
			scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
			ordinal INTEGER NOT NULL,
			name TEXT NOT NULL,
			address TEXT NOT NULL,
			PRIMARY KEY (scan_id, ordinal)
		)`,
		`CREATE INDEX scan_targets_address_idx ON scan_targets(address)`,
		`CREATE TABLE scan_ports (
			scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
			ordinal INTEGER NOT NULL,
			port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),
			PRIMARY KEY (scan_id, ordinal)
		)`,
		`CREATE TABLE service_observations (
			id TEXT PRIMARY KEY,
			scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
			ordinal INTEGER NOT NULL,
			target TEXT NOT NULL,
			address TEXT NOT NULL,
			port INTEGER NOT NULL,
			protocol TEXT NOT NULL,
			product TEXT NOT NULL DEFAULT '',
			version TEXT NOT NULL DEFAULT '',
			confidence TEXT NOT NULL,
			evidence TEXT NOT NULL,
			observed_at TEXT NOT NULL
		)`,
		`CREATE INDEX observations_product_version_idx ON service_observations(product, version)`,
		`CREATE INDEX observations_scan_idx ON service_observations(scan_id, ordinal)`,
		`CREATE TABLE observation_metadata (
			observation_id TEXT NOT NULL REFERENCES service_observations(id) ON DELETE CASCADE,
			key TEXT NOT NULL,
			value TEXT NOT NULL,
			PRIMARY KEY (observation_id, key)
		)`,
		`CREATE TABLE findings (
			id TEXT PRIMARY KEY,
			scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
			ordinal INTEGER NOT NULL,
			check_id TEXT NOT NULL,
			target TEXT NOT NULL,
			address TEXT NOT NULL,
			port INTEGER NOT NULL,
			service TEXT NOT NULL,
			severity TEXT NOT NULL,
			title TEXT NOT NULL,
			evidence TEXT NOT NULL,
			remediation TEXT NOT NULL,
			observed_at TEXT NOT NULL
		)`,
		`CREATE INDEX findings_scan_idx ON findings(scan_id, ordinal)`,
		`CREATE INDEX findings_check_severity_idx ON findings(check_id, severity)`,
		`CREATE TABLE app_metadata (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		)`,
	}
	for _, statement := range statements {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("apply schema migration 1: %w", err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version, applied_at) VALUES(1, ?)`, formatTime(time.Now().UTC())); err != nil {
		return fmt.Errorf("record schema migration 1: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit schema migration 1: %w", err)
	}
	return nil
}

func (s *SQLiteStore) Save(scan model.Scan) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin scan save: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM scans WHERE id = ?`, scan.ID); err != nil {
		return fmt.Errorf("replace scan: %w", err)
	}
	if _, err := tx.Exec(`
		INSERT INTO scans(id, name, status, error, total_checks, done_checks, created_at, started_at, completed_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, scan.ID, scan.Name, scan.Status, scan.Error, scan.TotalChecks, scan.DoneChecks,
		formatTime(scan.CreatedAt), formatOptionalTime(scan.StartedAt), formatOptionalTime(scan.CompletedAt)); err != nil {
		return fmt.Errorf("insert scan: %w", err)
	}
	for index, target := range scan.Targets {
		if _, err := tx.Exec(`INSERT INTO scan_targets(scan_id, ordinal, name, address) VALUES(?, ?, ?, ?)`,
			scan.ID, index, target.Name, target.Address); err != nil {
			return fmt.Errorf("insert scan target: %w", err)
		}
	}
	for index, port := range scan.Ports {
		if _, err := tx.Exec(`INSERT INTO scan_ports(scan_id, ordinal, port) VALUES(?, ?, ?)`,
			scan.ID, index, port); err != nil {
			return fmt.Errorf("insert scan port: %w", err)
		}
	}
	for index, observation := range scan.Observations {
		if _, err := tx.Exec(`
			INSERT INTO service_observations(
				id, scan_id, ordinal, target, address, port, protocol, product, version, confidence, evidence, observed_at
			) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, observation.ID, scan.ID, index, observation.Target, observation.Address, observation.Port,
			observation.Protocol, observation.Product, observation.Version, observation.Confidence,
			observation.Evidence, formatTime(observation.ObservedAt)); err != nil {
			return fmt.Errorf("insert service observation: %w", err)
		}
		for key, value := range observation.Metadata {
			if _, err := tx.Exec(`INSERT INTO observation_metadata(observation_id, key, value) VALUES(?, ?, ?)`,
				observation.ID, key, value); err != nil {
				return fmt.Errorf("insert observation metadata: %w", err)
			}
		}
	}
	for index, finding := range scan.Findings {
		if _, err := tx.Exec(`
			INSERT INTO findings(
				id, scan_id, ordinal, check_id, target, address, port, service, severity, title, evidence, remediation, observed_at
			) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, finding.ID, scan.ID, index, finding.CheckID, finding.Target, finding.Address, finding.Port,
			finding.Service, finding.Severity, finding.Title, finding.Evidence, finding.Remediation,
			formatTime(finding.ObservedAt)); err != nil {
			return fmt.Errorf("insert finding: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit scan save: %w", err)
	}
	return nil
}

func (s *SQLiteStore) Get(id string) (model.Scan, error) {
	var scan model.Scan
	var status string
	var created string
	var started, completed sql.NullString
	err := s.db.QueryRow(`
		SELECT id, name, status, error, total_checks, done_checks, created_at, started_at, completed_at
		FROM scans WHERE id = ?
	`, id).Scan(&scan.ID, &scan.Name, &status, &scan.Error, &scan.TotalChecks, &scan.DoneChecks,
		&created, &started, &completed)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Scan{}, ErrNotFound
	}
	if err != nil {
		return model.Scan{}, fmt.Errorf("get scan: %w", err)
	}
	scan.Status = model.ScanStatus(status)
	if scan.CreatedAt, err = parseTime(created); err != nil {
		return model.Scan{}, err
	}
	if scan.StartedAt, err = parseOptionalTime(started); err != nil {
		return model.Scan{}, err
	}
	if scan.CompletedAt, err = parseOptionalTime(completed); err != nil {
		return model.Scan{}, err
	}
	if err := s.loadTargets(&scan); err != nil {
		return model.Scan{}, err
	}
	if err := s.loadPorts(&scan); err != nil {
		return model.Scan{}, err
	}
	if err := s.loadObservations(&scan); err != nil {
		return model.Scan{}, err
	}
	if err := s.loadFindings(&scan); err != nil {
		return model.Scan{}, err
	}
	return scan, nil
}

func (s *SQLiteStore) List() ([]model.Scan, error) {
	rows, err := s.db.Query(`SELECT id FROM scans ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list scan IDs: %w", err)
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("read scan ID: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, fmt.Errorf("iterate scan IDs: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close scan ID query: %w", err)
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

func (s *SQLiteStore) ReconcileInterrupted() error {
	now := formatTime(time.Now().UTC())
	_, err := s.db.Exec(`
		UPDATE scans
		SET status = ?, error = ?, completed_at = ?
		WHERE status IN (?, ?)
	`, model.StatusFailed, "scan interrupted by a previous process shutdown", now,
		model.StatusQueued, model.StatusRunning)
	if err != nil {
		return fmt.Errorf("reconcile interrupted scans: %w", err)
	}
	return nil
}

func (s *SQLiteStore) loadTargets(scan *model.Scan) error {
	rows, err := s.db.Query(`SELECT name, address FROM scan_targets WHERE scan_id = ? ORDER BY ordinal`, scan.ID)
	if err != nil {
		return fmt.Errorf("load scan targets: %w", err)
	}
	defer rows.Close()
	scan.Targets = []model.Target{}
	for rows.Next() {
		var target model.Target
		if err := rows.Scan(&target.Name, &target.Address); err != nil {
			return fmt.Errorf("read scan target: %w", err)
		}
		scan.Targets = append(scan.Targets, target)
	}
	return rows.Err()
}

func (s *SQLiteStore) loadPorts(scan *model.Scan) error {
	rows, err := s.db.Query(`SELECT port FROM scan_ports WHERE scan_id = ? ORDER BY ordinal`, scan.ID)
	if err != nil {
		return fmt.Errorf("load scan ports: %w", err)
	}
	defer rows.Close()
	scan.Ports = []int{}
	for rows.Next() {
		var port int
		if err := rows.Scan(&port); err != nil {
			return fmt.Errorf("read scan port: %w", err)
		}
		scan.Ports = append(scan.Ports, port)
	}
	return rows.Err()
}

func (s *SQLiteStore) loadObservations(scan *model.Scan) error {
	rows, err := s.db.Query(`
		SELECT id, target, address, port, protocol, product, version, confidence, evidence, observed_at
		FROM service_observations WHERE scan_id = ? ORDER BY ordinal
	`, scan.ID)
	if err != nil {
		return fmt.Errorf("load service observations: %w", err)
	}
	scan.Observations = []model.ServiceObservation{}
	for rows.Next() {
		var observation model.ServiceObservation
		var observed string
		if err := rows.Scan(&observation.ID, &observation.Target, &observation.Address, &observation.Port,
			&observation.Protocol, &observation.Product, &observation.Version, &observation.Confidence,
			&observation.Evidence, &observed); err != nil {
			_ = rows.Close()
			return fmt.Errorf("read service observation: %w", err)
		}
		if observation.ObservedAt, err = parseTime(observed); err != nil {
			_ = rows.Close()
			return err
		}
		scan.Observations = append(scan.Observations, observation)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for index := range scan.Observations {
		metadataRows, err := s.db.Query(`SELECT key, value FROM observation_metadata WHERE observation_id = ? ORDER BY key`,
			scan.Observations[index].ID)
		if err != nil {
			return fmt.Errorf("load observation metadata: %w", err)
		}
		metadata := make(map[string]string)
		for metadataRows.Next() {
			var key, value string
			if err := metadataRows.Scan(&key, &value); err != nil {
				_ = metadataRows.Close()
				return fmt.Errorf("read observation metadata: %w", err)
			}
			metadata[key] = value
		}
		if err := metadataRows.Close(); err != nil {
			return err
		}
		if len(metadata) > 0 {
			scan.Observations[index].Metadata = metadata
		}
	}
	return nil
}

func (s *SQLiteStore) loadFindings(scan *model.Scan) error {
	rows, err := s.db.Query(`
		SELECT id, check_id, target, address, port, service, severity, title, evidence, remediation, observed_at
		FROM findings WHERE scan_id = ? ORDER BY ordinal
	`, scan.ID)
	if err != nil {
		return fmt.Errorf("load findings: %w", err)
	}
	defer rows.Close()
	scan.Findings = []model.Finding{}
	for rows.Next() {
		var finding model.Finding
		var observed string
		if err := rows.Scan(&finding.ID, &finding.CheckID, &finding.Target, &finding.Address, &finding.Port,
			&finding.Service, &finding.Severity, &finding.Title, &finding.Evidence,
			&finding.Remediation, &observed); err != nil {
			return fmt.Errorf("read finding: %w", err)
		}
		if finding.ObservedAt, err = parseTime(observed); err != nil {
			return err
		}
		scan.Findings = append(scan.Findings, finding)
	}
	return rows.Err()
}

func (s *SQLiteStore) importLegacyJSON(path string) error {
	if path == "" {
		return nil
	}
	var imported string
	err := s.db.QueryRow(`SELECT value FROM app_metadata WHERE key = 'legacy_json_imported'`).Scan(&imported)
	if err == nil {
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("check legacy import state: %w", err)
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s.markLegacyImport("no legacy file found")
	}
	if err != nil {
		return fmt.Errorf("read legacy scan file: %w", err)
	}
	var scans map[string]model.Scan
	if err := json.Unmarshal(data, &scans); err != nil {
		return fmt.Errorf("decode legacy scan file: %w", err)
	}
	for _, scan := range scans {
		if err := s.Save(migrateLegacyObservations(scan)); err != nil {
			return fmt.Errorf("import legacy scan %q: %w", scan.ID, err)
		}
	}
	archivePath := path + ".imported"
	if err := os.Rename(path, archivePath); err != nil {
		return fmt.Errorf("archive imported legacy scan file: %w", err)
	}
	if err := s.markLegacyImport(fmt.Sprintf("imported %d scans", len(scans))); err != nil {
		return err
	}
	return nil
}

func (s *SQLiteStore) markLegacyImport(value string) error {
	_, err := s.db.Exec(`INSERT INTO app_metadata(key, value) VALUES('legacy_json_imported', ?)`, value)
	if err != nil {
		return fmt.Errorf("record legacy import: %w", err)
	}
	return nil
}

func migrateLegacyObservations(scan model.Scan) model.Scan {
	if scan.Observations == nil {
		scan.Observations = []model.ServiceObservation{}
	}
	if scan.Findings == nil {
		scan.Findings = []model.Finding{}
	}
	currentFindings := scan.Findings[:0]
	for _, finding := range scan.Findings {
		if finding.CheckID == "" && finding.Severity == "info" {
			scan.Observations = append(scan.Observations, model.ServiceObservation{
				ID: finding.ID, Target: finding.Target, Address: finding.Address,
				Port: finding.Port, Protocol: finding.Service, Confidence: "low",
				Evidence: finding.Evidence, ObservedAt: finding.ObservedAt,
			})
			continue
		}
		currentFindings = append(currentFindings, finding)
	}
	scan.Findings = currentFindings
	return scan
}

func formatTime(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}

func formatOptionalTime(value *time.Time) any {
	if value == nil {
		return nil
	}
	return formatTime(*value)
}

func parseTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse stored timestamp %q: %w", value, err)
	}
	return parsed, nil
}

func parseOptionalTime(value sql.NullString) (*time.Time, error) {
	if !value.Valid {
		return nil, nil
	}
	parsed, err := parseTime(value.String)
	if err != nil {
		return nil, err
	}
	return &parsed, nil
}
