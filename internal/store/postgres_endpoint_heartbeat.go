package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"mossward/internal/model"
)

const (
	defaultMissedHeartbeatMinutes = 5
	defaultStaleHeartbeatMinutes  = 30
	maximumMissedHeartbeatMinutes = 24 * 60
	maximumStaleHeartbeatMinutes  = 7 * 24 * 60
)

func migratePostgreSQLEndpointHeartbeatSettings(ctx context.Context, tx *sql.Tx) error {
	statement := fmt.Sprintf(`CREATE TABLE endpoint_heartbeat_settings (
		singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK(singleton),enabled BOOLEAN NOT NULL,
		missed_after_minutes INTEGER NOT NULL CHECK(missed_after_minutes BETWEEN 1 AND %d),
		stale_after_minutes INTEGER NOT NULL CHECK(stale_after_minutes > missed_after_minutes AND stale_after_minutes <= %d),
		updated_by TEXT NOT NULL DEFAULT '',updated_at TIMESTAMPTZ
	)`, maximumMissedHeartbeatMinutes, maximumStaleHeartbeatMinutes)
	if _, err := tx.ExecContext(ctx, statement); err != nil {
		return fmt.Errorf("migrate PostgreSQL endpoint heartbeat settings: %w", err)
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO endpoint_heartbeat_settings
		(singleton,enabled,missed_after_minutes,stale_after_minutes) VALUES(TRUE,TRUE,$1,$2)`,
		defaultMissedHeartbeatMinutes, defaultStaleHeartbeatMinutes)
	if err != nil {
		return fmt.Errorf("initialize PostgreSQL endpoint heartbeat settings: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version,applied_at) VALUES(23,$1)`, time.Now().UTC()); err != nil {
		return fmt.Errorf("record PostgreSQL endpoint-heartbeat migration: %w", err)
	}
	return nil
}

func (s *PostgreSQLStore) EndpointHeartbeatSettings() (model.EndpointHeartbeatSettings, error) {
	var settings model.EndpointHeartbeatSettings
	var updatedAt sql.NullTime
	err := s.db.QueryRow(`SELECT enabled,missed_after_minutes,stale_after_minutes,updated_by,updated_at
		FROM endpoint_heartbeat_settings WHERE singleton=TRUE`).Scan(&settings.Enabled, &settings.MissedAfterMinutes,
		&settings.StaleAfterMinutes, &settings.UpdatedBy, &updatedAt)
	if err != nil {
		return settings, fmt.Errorf("read PostgreSQL endpoint heartbeat settings: %w", err)
	}
	if updatedAt.Valid {
		settings.UpdatedAt = updatedAt.Time
	}
	return settings, nil
}

func (s *PostgreSQLStore) SetEndpointHeartbeatSettings(settings model.EndpointHeartbeatSettings, event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL endpoint heartbeat-settings update: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.Exec(`UPDATE endpoint_heartbeat_settings SET enabled=$1,missed_after_minutes=$2,
		stale_after_minutes=$3,updated_by=$4,updated_at=$5 WHERE singleton=TRUE`, settings.Enabled,
		settings.MissedAfterMinutes, settings.StaleAfterMinutes, settings.UpdatedBy, settings.UpdatedAt)
	if err != nil {
		return fmt.Errorf("update PostgreSQL endpoint heartbeat settings: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return ErrNotFound
	}
	if err := insertPostgreSQLAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}
