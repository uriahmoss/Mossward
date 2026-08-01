package store

import (
	"fmt"
	"time"
)

func (s *SQLiteStore) applyIdentityMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin identity schema migration: %w", err)
	}
	defer tx.Rollback()
	for _, statement := range identitySchemaStatements {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("apply identity schema migration: %w", err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version, applied_at) VALUES(3, ?)`, formatTime(time.Now().UTC())); err != nil {
		return fmt.Errorf("record identity schema migration: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit identity schema migration: %w", err)
	}
	return nil
}

var identitySchemaStatements = []string{
	`CREATE TABLE users (
		id TEXT PRIMARY KEY, email TEXT NOT NULL COLLATE NOCASE UNIQUE,
		display_name TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('administrator','analyst','viewer')),
		status TEXT NOT NULL CHECK(status IN ('invited','active','disabled')),
		password_hash TEXT NOT NULL DEFAULT '', mfa_required INTEGER NOT NULL DEFAULT 0,
		created_at TEXT NOT NULL, updated_at TEXT NOT NULL, last_login_at TEXT
	)`,
	`CREATE TABLE invitations (
		id TEXT PRIMARY KEY, email TEXT NOT NULL COLLATE NOCASE, role TEXT NOT NULL,
		token_hash BLOB NOT NULL UNIQUE, invited_by TEXT NOT NULL REFERENCES users(id),
		expires_at TEXT NOT NULL, accepted_at TEXT, created_at TEXT NOT NULL
	)`,
	`CREATE INDEX invitations_email_idx ON invitations(email, accepted_at)`,
	`CREATE TABLE sessions (
		id_hash BLOB PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		created_at TEXT NOT NULL, expires_at TEXT NOT NULL, last_seen_at TEXT NOT NULL,
		mfa_verified_at TEXT, source_ip TEXT NOT NULL DEFAULT '', user_agent_hash BLOB
	)`,
	`CREATE INDEX sessions_user_idx ON sessions(user_id, expires_at)`,
	`CREATE TABLE login_attempts (
		key_hash BLOB PRIMARY KEY, failures INTEGER NOT NULL DEFAULT 0,
		window_started_at TEXT NOT NULL, blocked_until TEXT
	)`,
	`CREATE TABLE totp_credentials (
		user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
		secret_ciphertext BLOB NOT NULL, created_at TEXT NOT NULL, verified_at TEXT NOT NULL,
		last_counter INTEGER NOT NULL DEFAULT -1
	)`,
	`CREATE TABLE recovery_codes (
		user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		code_hash BLOB NOT NULL, used_at TEXT, created_at TEXT NOT NULL,
		PRIMARY KEY(user_id, code_hash)
	)`,
	`CREATE TABLE webauthn_credentials (
		credential_id BLOB PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		public_key BLOB NOT NULL, attestation_type TEXT NOT NULL DEFAULT '', transports TEXT NOT NULL DEFAULT '[]',
		sign_count INTEGER NOT NULL DEFAULT 0, backup_eligible INTEGER NOT NULL DEFAULT 0,
		backup_state INTEGER NOT NULL DEFAULT 0, name TEXT NOT NULL, created_at TEXT NOT NULL,
		last_used_at TEXT
	)`,
	`CREATE INDEX webauthn_credentials_user_idx ON webauthn_credentials(user_id)`,
	`CREATE TABLE authentication_ceremonies (
		id_hash BLOB PRIMARY KEY, user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
		kind TEXT NOT NULL CHECK(kind IN ('webauthn_register','webauthn_login','oidc')),
		state_ciphertext BLOB NOT NULL, expires_at TEXT NOT NULL, created_at TEXT NOT NULL
	)`,
	`CREATE TABLE oidc_providers (
		id TEXT PRIMARY KEY, name TEXT NOT NULL, issuer_url TEXT NOT NULL UNIQUE,
		client_id TEXT NOT NULL, client_secret_ciphertext BLOB NOT NULL,
		provisioning_mode TEXT NOT NULL CHECK(provisioning_mode IN ('invite_only','jit')),
		allowed_tenant_id TEXT NOT NULL DEFAULT '', allowed_email_domains TEXT NOT NULL DEFAULT '[]',
		allowed_groups TEXT NOT NULL DEFAULT '[]', role_mappings TEXT NOT NULL DEFAULT '{}',
		default_role TEXT NOT NULL DEFAULT 'viewer', enabled INTEGER NOT NULL DEFAULT 0,
		created_at TEXT NOT NULL, updated_at TEXT NOT NULL
	)`,
	`CREATE TABLE external_identities (
		provider_id TEXT NOT NULL REFERENCES oidc_providers(id) ON DELETE CASCADE,
		subject TEXT NOT NULL, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		tenant_id TEXT NOT NULL DEFAULT '', email TEXT NOT NULL COLLATE NOCASE,
		created_at TEXT NOT NULL, last_login_at TEXT,
		PRIMARY KEY(provider_id, subject), UNIQUE(provider_id, user_id)
	)`,
	`CREATE TABLE audit_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT, occurred_at TEXT NOT NULL,
		actor_id TEXT REFERENCES users(id) ON DELETE SET NULL, action TEXT NOT NULL,
		severity TEXT NOT NULL CHECK(severity IN ('info','warning','error')),
		target_type TEXT NOT NULL DEFAULT '', target_id TEXT NOT NULL DEFAULT '',
		source_ip TEXT NOT NULL DEFAULT '', details TEXT NOT NULL DEFAULT '{}'
	)`,
	`CREATE INDEX audit_events_time_idx ON audit_events(occurred_at DESC)`,
	`CREATE TABLE scope_policies (
		id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, allowed_cidrs TEXT NOT NULL,
		allowed_ports TEXT NOT NULL, max_targets INTEGER NOT NULL,
		enabled INTEGER NOT NULL DEFAULT 1, created_by TEXT REFERENCES users(id),
		created_at TEXT NOT NULL, updated_at TEXT NOT NULL
	)`,
}
