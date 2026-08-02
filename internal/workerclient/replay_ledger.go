package workerclient

import (
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"mossward/internal/model"

	_ "modernc.org/sqlite"
)

const (
	replayLedgerSchemaVersion = 1
	replayLedgerFileMode      = 0o600
	replayLedgerDirectoryMode = 0o700
)

var ErrJobReplay = errors.New("scanner-worker job was already claimed")

type ReplayLedger struct {
	db *sql.DB
}

func OpenReplayLedger(path string) (*ReplayLedger, error) {
	if err := prepareReplayLedgerPath(path); err != nil {
		return nil, err
	}
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve scanner-worker replay ledger path: %w", err)
	}
	database, err := sql.Open("sqlite", replayLedgerDSN(absolutePath))
	if err != nil {
		return nil, fmt.Errorf("open scanner-worker replay ledger: %w", err)
	}
	database.SetMaxOpenConns(1)
	ledger := &ReplayLedger{db: database}
	if err := ledger.migrate(); err != nil {
		_ = database.Close()
		return nil, err
	}
	if err := os.Chmod(path, replayLedgerFileMode); err != nil {
		_ = database.Close()
		return nil, fmt.Errorf("secure scanner-worker replay ledger: %w", err)
	}
	return ledger, nil
}

func prepareReplayLedgerPath(path string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("scanner-worker replay ledger path is required")
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, replayLedgerDirectoryMode); err != nil {
		return fmt.Errorf("create scanner-worker replay ledger directory: %w", err)
	}
	if runtime.GOOS != "windows" {
		directoryInfo, err := os.Stat(directory)
		if err != nil {
			return fmt.Errorf("inspect scanner-worker replay ledger directory: %w", err)
		}
		if directoryInfo.Mode().Perm()&0o077 != 0 {
			return errors.New("scanner-worker replay ledger directory permissions are too broad")
		}
		if info, err := os.Stat(path); err == nil && info.Mode().Perm()&0o077 != 0 {
			return errors.New("scanner-worker replay ledger permissions are too broad")
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect scanner-worker replay ledger: %w", err)
		}
	}
	return nil
}

func replayLedgerDSN(path string) string {
	slashPath := filepath.ToSlash(path)
	if filepath.VolumeName(path) != "" && !strings.HasPrefix(slashPath, "/") {
		slashPath = "/" + slashPath
	}
	return (&url.URL{Scheme: "file", Path: slashPath,
		RawQuery: "_pragma=journal_mode(DELETE)&_pragma=busy_timeout(5000)&_pragma=synchronous(FULL)"}).String()
}

func (l *ReplayLedger) migrate() error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS replay_ledger_metadata (schema_version INTEGER NOT NULL)`,
		`INSERT INTO replay_ledger_metadata(schema_version) SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM replay_ledger_metadata)`,
		`CREATE TABLE IF NOT EXISTS claimed_jobs (job_id TEXT PRIMARY KEY,worker_id TEXT NOT NULL,signing_key_id TEXT NOT NULL,signature_digest BLOB NOT NULL,expires_at TEXT NOT NULL,claimed_at TEXT NOT NULL)`,
	}
	for _, statement := range statements {
		if _, err := l.db.Exec(statement); err != nil {
			return fmt.Errorf("migrate scanner-worker replay ledger: %w", err)
		}
	}
	var version int
	if err := l.db.QueryRow(`SELECT schema_version FROM replay_ledger_metadata LIMIT 1`).Scan(&version); err != nil {
		return fmt.Errorf("read scanner-worker replay ledger schema: %w", err)
	}
	if version != replayLedgerSchemaVersion {
		return fmt.Errorf("unsupported scanner-worker replay ledger schema %d", version)
	}
	return nil
}

func (l *ReplayLedger) Claim(envelope model.SignedWorkerJob, claimedAt time.Time) error {
	if envelope.Job.ID == "" || envelope.Job.WorkerID == "" || envelope.KeyID == "" || envelope.Signature == "" ||
		envelope.Job.ExpiresAt.IsZero() || claimedAt.IsZero() || !claimedAt.Before(envelope.Job.ExpiresAt) {
		return errors.New("scanner-worker replay claim is incomplete")
	}
	digest := sha256.Sum256([]byte(envelope.Signature))
	result, err := l.db.Exec(`INSERT OR IGNORE INTO claimed_jobs(job_id,worker_id,signing_key_id,signature_digest,expires_at,claimed_at) VALUES(?,?,?,?,?,?)`, envelope.Job.ID, envelope.Job.WorkerID, envelope.KeyID, digest[:], envelope.Job.ExpiresAt.UTC().Format(time.RFC3339Nano), claimedAt.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("claim scanner-worker job: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read scanner-worker replay claim result: %w", err)
	}
	if changed != 1 {
		return ErrJobReplay
	}
	return nil
}

func (l *ReplayLedger) Close() error {
	return l.db.Close()
}
