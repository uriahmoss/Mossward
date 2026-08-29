package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

func migratePostgreSQLScannerWorkers(ctx context.Context, tx *sql.Tx) error {
	statements := []string{
		`CREATE TABLE scanner_worker_enrollment_tokens (
			id TEXT PRIMARY KEY,name TEXT NOT NULL,site_id TEXT NOT NULL DEFAULT '',token_hash BYTEA NOT NULL UNIQUE,
			allowed_cidrs TEXT NOT NULL,allowed_ports TEXT NOT NULL,max_concurrent INTEGER NOT NULL CHECK(max_concurrent BETWEEN 1 AND 256),
			rate_limit_per_second INTEGER NOT NULL CHECK(rate_limit_per_second BETWEEN 0 AND 1000),
			created_by TEXT NOT NULL REFERENCES users(id),created_at TIMESTAMPTZ NOT NULL,expires_at TIMESTAMPTZ NOT NULL,used_at TIMESTAMPTZ
		)`,
		`CREATE INDEX scanner_worker_tokens_expiry_idx ON scanner_worker_enrollment_tokens(expires_at,used_at)`,
		`CREATE TABLE scanner_workers (
			id TEXT PRIMARY KEY,name TEXT NOT NULL,site_id TEXT NOT NULL DEFAULT '',status TEXT NOT NULL CHECK(status IN ('active','revoked')),
			certificate_serial TEXT NOT NULL UNIQUE,certificate_pem TEXT NOT NULL,allowed_cidrs TEXT NOT NULL,allowed_ports TEXT NOT NULL,
			max_concurrent INTEGER NOT NULL CHECK(max_concurrent BETWEEN 1 AND 256),
			rate_limit_per_second INTEGER NOT NULL CHECK(rate_limit_per_second BETWEEN 0 AND 1000),
			enrolled_at TIMESTAMPTZ NOT NULL,expires_at TIMESTAMPTZ NOT NULL,last_seen_at TIMESTAMPTZ,revoked_at TIMESTAMPTZ,
			revocation_reason TEXT NOT NULL DEFAULT '',software_version TEXT NOT NULL DEFAULT '',operating_system TEXT NOT NULL DEFAULT '',
			architecture TEXT NOT NULL DEFAULT '',capabilities TEXT NOT NULL DEFAULT '[]',
			available_concurrency INTEGER NOT NULL DEFAULT 0 CHECK(available_concurrency BETWEEN 0 AND 256),
			health TEXT NOT NULL DEFAULT 'healthy' CHECK(health IN ('healthy','degraded')),health_message TEXT NOT NULL DEFAULT '',
			dispatch_enabled BOOLEAN NOT NULL DEFAULT TRUE
		)`,
		`CREATE INDEX scanner_workers_status_idx ON scanner_workers(status,name)`,
		`CREATE INDEX scanner_workers_site_status_idx ON scanner_workers(site_id,status)`,
		`CREATE INDEX scanner_workers_dispatch_idx ON scanner_workers(status,dispatch_enabled)`,
		`CREATE TABLE scanner_worker_dispatch_settings (singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK(singleton),enabled BOOLEAN NOT NULL)`,
		`INSERT INTO scanner_worker_dispatch_settings(singleton,enabled) VALUES(TRUE,TRUE)`,
		`CREATE TABLE scanner_worker_jobs (
			id TEXT PRIMARY KEY,worker_id TEXT NOT NULL REFERENCES scanner_workers(id),scan_id TEXT NOT NULL,
			status TEXT NOT NULL CHECK(status IN ('pending','leased','completed','canceled','expired')),signed_envelope TEXT NOT NULL,
			issued_at TIMESTAMPTZ NOT NULL,expires_at TIMESTAMPTZ NOT NULL,created_at TIMESTAMPTZ NOT NULL,
			lease_token_hash BYTEA,lease_expires_at TIMESTAMPTZ,lease_attempt INTEGER NOT NULL DEFAULT 0 CHECK(lease_attempt >= 0),
			result_id TEXT,result_outcome TEXT,completed_at TIMESTAMPTZ
		)`,
		`CREATE INDEX scanner_worker_jobs_worker_status_idx ON scanner_worker_jobs(worker_id,status,expires_at)`,
		`CREATE INDEX scanner_worker_jobs_scan_idx ON scanner_worker_jobs(scan_id)`,
		`CREATE UNIQUE INDEX scanner_worker_jobs_result_id_idx ON scanner_worker_jobs(result_id) WHERE result_id IS NOT NULL`,
		`CREATE TABLE scanner_worker_evidence_batches (
			batch_id TEXT PRIMARY KEY,job_id TEXT NOT NULL REFERENCES scanner_worker_jobs(id),worker_id TEXT NOT NULL REFERENCES scanner_workers(id),
			scan_id TEXT NOT NULL,sequence INTEGER NOT NULL CHECK(sequence > 0),final BOOLEAN NOT NULL,certificate_serial TEXT NOT NULL,
			signed_envelope TEXT NOT NULL,collected_at TIMESTAMPTZ NOT NULL,received_at TIMESTAMPTZ NOT NULL,UNIQUE(job_id,sequence)
		)`,
		`CREATE INDEX scanner_worker_evidence_job_idx ON scanner_worker_evidence_batches(job_id,sequence)`,
		`CREATE INDEX scanner_worker_evidence_scan_idx ON scanner_worker_evidence_batches(scan_id,received_at)`,
		`CREATE TABLE scanner_worker_job_checkpoints (
			job_id TEXT NOT NULL REFERENCES scanner_worker_jobs(id),worker_id TEXT NOT NULL REFERENCES scanner_workers(id),scan_id TEXT NOT NULL,
			address TEXT NOT NULL,port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),completed_at TIMESTAMPTZ NOT NULL,
			batch_id TEXT NOT NULL REFERENCES scanner_worker_evidence_batches(batch_id),PRIMARY KEY(job_id,address,port)
		)`,
		`CREATE INDEX scanner_worker_checkpoints_scan_idx ON scanner_worker_job_checkpoints(scan_id,address,port)`,
		`CREATE TABLE scanner_worker_job_assignments (
			job_id TEXT NOT NULL REFERENCES scanner_worker_jobs(id),attempt INTEGER NOT NULL CHECK(attempt > 0),
			worker_id TEXT NOT NULL REFERENCES scanner_workers(id),signed_envelope TEXT NOT NULL,assigned_at TIMESTAMPTZ NOT NULL,
			reason TEXT NOT NULL,PRIMARY KEY(job_id,attempt)
		)`,
		`CREATE INDEX scanner_worker_job_assignments_worker_idx ON scanner_worker_job_assignments(worker_id,assigned_at)`,
		`CREATE TABLE scanner_worker_job_dead_letters (
			job_id TEXT PRIMARY KEY REFERENCES scanner_worker_jobs(id),scan_id TEXT NOT NULL,worker_id TEXT NOT NULL REFERENCES scanner_workers(id),
			failure_count INTEGER NOT NULL CHECK(failure_count > 0),reason TEXT NOT NULL,quarantined_at TIMESTAMPTZ NOT NULL
		)`,
		`CREATE INDEX scanner_worker_dead_letters_time_idx ON scanner_worker_job_dead_letters(quarantined_at DESC)`,
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("migrate PostgreSQL scanner workers: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version,applied_at) VALUES(18,$1)`, time.Now().UTC()); err != nil {
		return fmt.Errorf("record PostgreSQL scanner-worker migration: %w", err)
	}
	return nil
}
