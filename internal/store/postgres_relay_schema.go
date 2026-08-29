package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

const postgresMinutesPerDay = 24 * 60

func migratePostgreSQLRelayPolicies(ctx context.Context, tx *sql.Tx) error {
	statements := []string{
		`CREATE TABLE endpoint_relay_authorizations (
			id TEXT PRIMARY KEY,endpoint_id TEXT NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
			status TEXT NOT NULL CHECK(status IN ('active','revoked')),promotion_reason TEXT NOT NULL,
			promoted_by TEXT NOT NULL,promoted_at TIMESTAMPTZ NOT NULL,revocation_reason TEXT NOT NULL DEFAULT '',
			revoked_by TEXT NOT NULL DEFAULT '',revoked_at TIMESTAMPTZ
		)`,
		`CREATE UNIQUE INDEX endpoint_relay_one_active_idx ON endpoint_relay_authorizations(endpoint_id) WHERE status='active'`,
		`CREATE INDEX endpoint_relay_history_idx ON endpoint_relay_authorizations(endpoint_id,promoted_at DESC)`,
		`CREATE TABLE relay_downstream_authorizations (
			id TEXT PRIMARY KEY,relay_endpoint_id TEXT NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
			downstream_endpoint_id TEXT NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
			status TEXT NOT NULL CHECK(status IN ('active','revoked')),authorization_reason TEXT NOT NULL,
			authorized_by TEXT NOT NULL,authorized_at TIMESTAMPTZ NOT NULL,revocation_reason TEXT NOT NULL DEFAULT '',
			revoked_by TEXT NOT NULL DEFAULT '',revoked_at TIMESTAMPTZ,
			CHECK(relay_endpoint_id <> downstream_endpoint_id)
		)`,
		`CREATE UNIQUE INDEX relay_downstream_one_active_relay_idx ON relay_downstream_authorizations(downstream_endpoint_id) WHERE status='active'`,
		`CREATE INDEX relay_downstream_relay_history_idx ON relay_downstream_authorizations(relay_endpoint_id,authorized_at DESC)`,
		fmt.Sprintf(`CREATE TABLE relay_upload_windows (
			id TEXT PRIMARY KEY,name TEXT NOT NULL,target_type TEXT NOT NULL CHECK(target_type IN ('endpoint','group')),
			target_id TEXT NOT NULL,timezone TEXT NOT NULL,days_json JSONB NOT NULL,
			start_minute INTEGER NOT NULL CHECK(start_minute >= 0 AND start_minute < %d),
			end_minute INTEGER NOT NULL CHECK(end_minute >= 0 AND end_minute < %d),enabled BOOLEAN NOT NULL,
			reason TEXT NOT NULL,created_by TEXT NOT NULL,created_at TIMESTAMPTZ NOT NULL,
			updated_by TEXT NOT NULL,updated_at TIMESTAMPTZ NOT NULL,CHECK(start_minute <> end_minute)
		)`, postgresMinutesPerDay, postgresMinutesPerDay),
		`CREATE INDEX relay_upload_windows_target_idx ON relay_upload_windows(target_type,target_id,enabled)`,
		fmt.Sprintf(`CREATE TABLE delayed_heartbeat_policies (
			target_type TEXT NOT NULL CHECK(target_type IN ('endpoint','group')),target_id TEXT NOT NULL,
			allow_delayed_heartbeats BOOLEAN NOT NULL,post_window_grace_minutes INTEGER NOT NULL DEFAULT 0
			CHECK(post_window_grace_minutes BETWEEN 0 AND %d),reason TEXT NOT NULL,updated_by TEXT NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL,PRIMARY KEY(target_type,target_id),
			CHECK(allow_delayed_heartbeats OR post_window_grace_minutes=0)
		)`, postgresMinutesPerDay),
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("migrate PostgreSQL relay policies: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version,applied_at) VALUES(20,$1)`, time.Now().UTC()); err != nil {
		return fmt.Errorf("record PostgreSQL relay-policy migration: %w", err)
	}
	return nil
}
