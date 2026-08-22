package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"mossward/internal/model"
)

func (s *PostgreSQLStore) LoginThrottle(keyHash []byte, now time.Time) (time.Time, bool, error) {
	var blocked sql.NullTime
	err := s.db.QueryRow(`SELECT blocked_until FROM login_attempts WHERE key_hash=$1`, keyHash).Scan(&blocked)
	if errors.Is(err, sql.ErrNoRows) || !blocked.Valid {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, fmt.Errorf("load PostgreSQL login throttle: %w", err)
	}
	until := blocked.Time.UTC()
	return until, now.Before(until), nil
}

func (s *PostgreSQLStore) RecordLoginFailure(keyHash []byte, now time.Time, window time.Duration, threshold int,
	baseBlock, maxBlock time.Duration) (time.Time, error) {
	if len(keyHash) == 0 || now.IsZero() || window <= 0 || threshold < 1 || baseBlock <= 0 || maxBlock < baseBlock {
		return time.Time{}, errors.New("PostgreSQL login throttle settings are invalid")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return time.Time{}, fmt.Errorf("begin PostgreSQL login failure: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`SELECT pg_advisory_xact_lock(hashtextextended(encode($1::bytea,'hex'),0))`, keyHash); err != nil {
		return time.Time{}, fmt.Errorf("lock PostgreSQL login failure key: %w", err)
	}
	failures, windowStart, err := loadPostgreSQLLoginFailure(tx, keyHash, now, window)
	if err != nil {
		return time.Time{}, err
	}
	blockedUntil := loginBlockTime(now, failures, threshold, baseBlock, maxBlock)
	var storedBlock any
	if !blockedUntil.IsZero() {
		storedBlock = blockedUntil.UTC()
	}
	_, err = tx.Exec(`INSERT INTO login_attempts(key_hash,failures,window_started_at,blocked_until) VALUES($1,$2,$3,$4)
		ON CONFLICT(key_hash) DO UPDATE SET failures=EXCLUDED.failures,window_started_at=EXCLUDED.window_started_at,blocked_until=EXCLUDED.blocked_until`,
		keyHash, failures, windowStart.UTC(), storedBlock)
	if err != nil {
		return time.Time{}, fmt.Errorf("store PostgreSQL login failure: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return time.Time{}, fmt.Errorf("commit PostgreSQL login failure: %w", err)
	}
	return blockedUntil, nil
}

func loadPostgreSQLLoginFailure(tx *sql.Tx, keyHash []byte, now time.Time, window time.Duration) (int, time.Time, error) {
	var failures int
	var started time.Time
	err := tx.QueryRow(`SELECT failures,window_started_at FROM login_attempts WHERE key_hash=$1 FOR UPDATE`, keyHash).Scan(&failures, &started)
	if errors.Is(err, sql.ErrNoRows) {
		return 1, now, nil
	}
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("load PostgreSQL login failure: %w", err)
	}
	if now.Sub(started) > window {
		return 1, now, nil
	}
	return failures + 1, started, nil
}

func loginBlockTime(now time.Time, failures, threshold int, baseBlock, maxBlock time.Duration) time.Time {
	if failures < threshold {
		return time.Time{}
	}
	block := time.Duration(failures-threshold+1) * baseBlock
	if block > maxBlock {
		block = maxBlock
	}
	return now.Add(block)
}

func (s *PostgreSQLStore) ClearLoginFailures(keyHashes ...[]byte) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL login-failure cleanup: %w", err)
	}
	defer tx.Rollback()
	for _, keyHash := range keyHashes {
		if _, err := tx.Exec(`DELETE FROM login_attempts WHERE key_hash=$1`, keyHash); err != nil {
			return fmt.Errorf("clear PostgreSQL login failures: %w", err)
		}
	}
	return tx.Commit()
}

func (s *PostgreSQLStore) TOTPSecret(userID string) ([]byte, int64, error) {
	var ciphertext []byte
	var counter int64
	err := s.db.QueryRow(`SELECT secret_ciphertext,last_counter FROM totp_credentials WHERE user_id=$1`, userID).Scan(&ciphertext, &counter)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, 0, ErrIdentityNotFound
	}
	if err != nil {
		return nil, 0, fmt.Errorf("load PostgreSQL TOTP credential: %w", err)
	}
	return ciphertext, counter, nil
}

func (s *PostgreSQLStore) ConsumeTOTPCounter(userID string, counter int64) (bool, error) {
	result, err := s.db.Exec(`UPDATE totp_credentials SET last_counter=$1 WHERE user_id=$2 AND last_counter<$1`, counter, userID)
	if err != nil {
		return false, fmt.Errorf("consume PostgreSQL TOTP counter: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("read PostgreSQL TOTP counter result: %w", err)
	}
	return changed == 1, nil
}

func (s *PostgreSQLStore) ConsumeRecoveryCode(userID string, codeHash []byte, usedAt time.Time, event model.AuditEvent) (bool, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return false, fmt.Errorf("begin PostgreSQL recovery code use: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.Exec(`UPDATE recovery_codes SET used_at=$1 WHERE user_id=$2 AND code_hash=$3 AND used_at IS NULL`,
		usedAt.UTC(), userID, codeHash)
	if err != nil {
		return false, fmt.Errorf("consume PostgreSQL recovery code: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("read PostgreSQL recovery code result: %w", err)
	}
	if changed != 1 {
		return false, nil
	}
	if err := insertPostgreSQLAuditEvent(tx, event); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit PostgreSQL recovery code use: %w", err)
	}
	return true, nil
}
