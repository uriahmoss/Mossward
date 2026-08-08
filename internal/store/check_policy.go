package store

import (
	"encoding/json"
	"fmt"
	"time"

	"mossward/internal/checkpolicy"
)

func (s *SQLiteStore) applyIntrusiveCheckPolicyMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin intrusive-check policy migration: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`CREATE TABLE intrusive_check_policy (id INTEGER PRIMARY KEY CHECK(id=1),enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),allowed_check_ids_json TEXT NOT NULL,updated_at TEXT NOT NULL)`); err != nil {
		return fmt.Errorf("apply intrusive-check policy migration: %w", err)
	}
	if _, err := tx.Exec(`INSERT INTO intrusive_check_policy(id,enabled,allowed_check_ids_json,updated_at) VALUES(1,0,'[]',?)`, formatTime(time.Now().UTC())); err != nil {
		return fmt.Errorf("initialize intrusive-check policy: %w", err)
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(35,?)`, formatTime(time.Now().UTC())); err != nil {
		return fmt.Errorf("record intrusive-check policy migration: %w", err)
	}
	return tx.Commit()
}

func (s *SQLiteStore) IntrusiveCheckPolicy() (checkpolicy.Policy, error) {
	var policy checkpolicy.Policy
	var enabled int
	var encoded, updated string
	if err := s.db.QueryRow(`SELECT enabled,allowed_check_ids_json,updated_at FROM intrusive_check_policy WHERE id=1`).Scan(&enabled, &encoded, &updated); err != nil {
		return policy, fmt.Errorf("load intrusive-check policy: %w", err)
	}
	if err := json.Unmarshal([]byte(encoded), &policy.AllowedCheckIDs); err != nil {
		return policy, fmt.Errorf("decode intrusive-check policy: %w", err)
	}
	policy.Enabled = enabled == 1
	policy.UpdatedAt, _ = parseTime(updated)
	return policy, nil
}

func (s *SQLiteStore) SaveIntrusiveCheckPolicy(policy checkpolicy.Policy) error {
	if err := checkpolicy.Validate(policy); err != nil {
		return err
	}
	encoded, err := json.Marshal(policy.AllowedCheckIDs)
	if err != nil {
		return fmt.Errorf("encode intrusive-check policy: %w", err)
	}
	_, err = s.db.Exec(`UPDATE intrusive_check_policy SET enabled=?,allowed_check_ids_json=?,updated_at=? WHERE id=1`, databaseBool(policy.Enabled), string(encoded), formatTime(policy.UpdatedAt))
	if err != nil {
		return fmt.Errorf("save intrusive-check policy: %w", err)
	}
	return nil
}

func databaseBool(value bool) int {
	if value {
		return 1
	}
	return 0
}
