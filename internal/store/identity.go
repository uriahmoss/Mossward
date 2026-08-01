package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"mossward/internal/model"
)

const sessionTouchInterval = 5 * time.Minute

func (s *SQLiteStore) SessionMFAVerifiedAt(idHash []byte, userID string, now time.Time) (*time.Time, error) {
	var value sql.NullString
	err := s.db.QueryRow(`SELECT mfa_verified_at FROM sessions WHERE id_hash=? AND user_id=? AND expires_at>?`,
		idHash, userID, formatTime(now)).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrIdentityNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("load session MFA verification: %w", err)
	}
	return parseOptionalTime(value)
}

func (s *SQLiteStore) UpdateSessionMFAVerifiedAt(idHash []byte, userID string, verifiedAt time.Time) error {
	result, err := s.db.Exec(`UPDATE sessions SET mfa_verified_at=? WHERE id_hash=? AND user_id=?`,
		formatTime(verifiedAt), idHash, userID)
	if err != nil {
		return fmt.Errorf("update session MFA verification: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read session MFA update result: %w", err)
	}
	if changed == 0 {
		return ErrIdentityNotFound
	}
	return nil
}

func (s *SQLiteStore) IdentityInitialized() (bool, error) {
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count); err != nil {
		return false, fmt.Errorf("count users: %w", err)
	}
	return count > 0, nil
}

func (s *SQLiteStore) BootstrapAdministrator(user model.User, passwordHash string, mfa model.BootstrapMFA, event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin administrator bootstrap: %w", err)
	}
	defer tx.Rollback()
	var count int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count); err != nil {
		return fmt.Errorf("check administrator bootstrap state: %w", err)
	}
	if count != 0 {
		return ErrAlreadyInitialized
	}
	if _, err := tx.Exec(`INSERT INTO users(id, email, display_name, role, status, password_hash, mfa_required, created_at, updated_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`, user.ID, normalizeEmail(user.Email), user.DisplayName,
		user.Role, user.Status, passwordHash, user.MFARequired, formatTime(user.CreatedAt), formatTime(user.UpdatedAt)); err != nil {
		return fmt.Errorf("create bootstrap administrator: %w", err)
	}
	if _, err := tx.Exec(`INSERT INTO totp_credentials(user_id, secret_ciphertext, created_at, verified_at)
		VALUES(?, ?, ?, ?)`, user.ID, mfa.TOTPSecretCiphertext, formatTime(user.CreatedAt), formatTime(user.CreatedAt)); err != nil {
		return fmt.Errorf("create bootstrap TOTP credential: %w", err)
	}
	for _, codeHash := range mfa.RecoveryCodeHashes {
		if _, err := tx.Exec(`INSERT INTO recovery_codes(user_id, code_hash, created_at) VALUES(?, ?, ?)`,
			user.ID, codeHash, formatTime(user.CreatedAt)); err != nil {
			return fmt.Errorf("create bootstrap recovery code: %w", err)
		}
	}
	if err := insertAuditEvent(tx, event); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit administrator bootstrap: %w", err)
	}
	return nil
}

func (s *SQLiteStore) LocalIdentityByEmail(email string) (model.LocalIdentity, error) {
	return s.localIdentity(`email=?`, normalizeEmail(email))
}

func (s *SQLiteStore) LocalIdentityByID(userID string) (model.LocalIdentity, error) {
	return s.localIdentity(`id=?`, userID)
}

func (s *SQLiteStore) localIdentity(predicate string, value any) (model.LocalIdentity, error) {
	var identity model.LocalIdentity
	var created, updated string
	var lastLogin sql.NullString
	err := s.db.QueryRow(`SELECT id, email, display_name, role, status, mfa_required, created_at, updated_at, last_login_at, password_hash
		FROM users WHERE `+predicate, value).Scan(&identity.User.ID, &identity.User.Email,
		&identity.User.DisplayName, &identity.User.Role, &identity.User.Status, &identity.User.MFARequired,
		&created, &updated, &lastLogin, &identity.PasswordHash)
	if errors.Is(err, sql.ErrNoRows) {
		return model.LocalIdentity{}, ErrIdentityNotFound
	}
	if err != nil {
		return model.LocalIdentity{}, fmt.Errorf("load local identity: %w", err)
	}
	if identity.User.CreatedAt, err = parseTime(created); err != nil {
		return model.LocalIdentity{}, err
	}
	if identity.User.UpdatedAt, err = parseTime(updated); err != nil {
		return model.LocalIdentity{}, err
	}
	if identity.User.LastLoginAt, err = parseOptionalTime(lastLogin); err != nil {
		return model.LocalIdentity{}, err
	}
	return identity, nil
}

func (s *SQLiteStore) CreateSession(session model.Session, event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin session creation: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO sessions(id_hash, public_id, user_id, created_at, expires_at, last_seen_at, mfa_verified_at, source_ip, user_agent_hash)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`, session.IDHash, session.PublicID, session.UserID, formatTime(session.CreatedAt),
		formatTime(session.ExpiresAt), formatTime(session.LastSeenAt), formatOptionalTime(session.MFAVerifiedAt),
		session.SourceIP, session.UserAgentHash); err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	if _, err := tx.Exec(`UPDATE users SET last_login_at=?, updated_at=? WHERE id=?`,
		formatTime(session.CreatedAt), formatTime(session.CreatedAt), session.UserID); err != nil {
		return fmt.Errorf("update last login: %w", err)
	}
	if err := insertAuditEvent(tx, event); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit session creation: %w", err)
	}
	return nil
}

func (s *SQLiteStore) AppendAuditEvent(event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin audit event: %w", err)
	}
	defer tx.Rollback()
	if err := insertAuditEvent(tx, event); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit audit event: %w", err)
	}
	return nil
}

func (s *SQLiteStore) LoginThrottle(keyHash []byte, now time.Time) (time.Time, bool, error) {
	var blocked sql.NullString
	err := s.db.QueryRow(`SELECT blocked_until FROM login_attempts WHERE key_hash=?`, keyHash).Scan(&blocked)
	if errors.Is(err, sql.ErrNoRows) || !blocked.Valid {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, fmt.Errorf("load login throttle: %w", err)
	}
	until, err := parseTime(blocked.String)
	if err != nil {
		return time.Time{}, false, err
	}
	return until, now.Before(until), nil
}

func (s *SQLiteStore) RecordLoginFailure(keyHash []byte, now time.Time, window time.Duration, threshold int, baseBlock, maxBlock time.Duration) (time.Time, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return time.Time{}, fmt.Errorf("begin login failure: %w", err)
	}
	defer tx.Rollback()
	var failures int
	var started string
	err = tx.QueryRow(`SELECT failures, window_started_at FROM login_attempts WHERE key_hash=?`, keyHash).Scan(&failures, &started)
	windowStart := now
	if err == nil {
		parsed, parseErr := parseTime(started)
		if parseErr != nil {
			return time.Time{}, parseErr
		}
		if now.Sub(parsed) <= window {
			windowStart, failures = parsed, failures+1
		} else {
			failures = 1
		}
	} else if errors.Is(err, sql.ErrNoRows) {
		failures = 1
	} else {
		return time.Time{}, fmt.Errorf("load login failure: %w", err)
	}
	var blockedUntil any
	var result time.Time
	if failures >= threshold {
		block := time.Duration(failures-threshold+1) * baseBlock
		if block > maxBlock {
			block = maxBlock
		}
		result = now.Add(block)
		blockedUntil = formatTime(result)
	}
	_, err = tx.Exec(`INSERT INTO login_attempts(key_hash, failures, window_started_at, blocked_until) VALUES(?, ?, ?, ?)
		ON CONFLICT(key_hash) DO UPDATE SET failures=excluded.failures, window_started_at=excluded.window_started_at, blocked_until=excluded.blocked_until`,
		keyHash, failures, formatTime(windowStart), blockedUntil)
	if err != nil {
		return time.Time{}, fmt.Errorf("store login failure: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return time.Time{}, fmt.Errorf("commit login failure: %w", err)
	}
	return result, nil
}

func (s *SQLiteStore) ClearLoginFailures(keyHashes ...[]byte) error {
	for _, keyHash := range keyHashes {
		if _, err := s.db.Exec(`DELETE FROM login_attempts WHERE key_hash=?`, keyHash); err != nil {
			return fmt.Errorf("clear login failures: %w", err)
		}
	}
	return nil
}

func (s *SQLiteStore) ListUserSessions(userID string, currentHash []byte, now time.Time) ([]model.SessionInfo, error) {
	rows, err := s.db.Query(`SELECT public_id, created_at, expires_at, last_seen_at, mfa_verified_at, source_ip, id_hash
		FROM sessions WHERE user_id=? AND expires_at>? ORDER BY created_at DESC`, userID, formatTime(now))
	if err != nil {
		return nil, fmt.Errorf("list user sessions: %w", err)
	}
	defer rows.Close()
	items := []model.SessionInfo{}
	for rows.Next() {
		var item model.SessionInfo
		var created, expires, seen string
		var mfa sql.NullString
		var hash []byte
		if err := rows.Scan(&item.ID, &created, &expires, &seen, &mfa, &item.SourceIP, &hash); err != nil {
			return nil, err
		}
		if item.CreatedAt, err = parseTime(created); err != nil {
			return nil, err
		}
		if item.ExpiresAt, err = parseTime(expires); err != nil {
			return nil, err
		}
		if item.LastSeenAt, err = parseTime(seen); err != nil {
			return nil, err
		}
		if item.MFAVerifiedAt, err = parseOptionalTime(mfa); err != nil {
			return nil, err
		}
		item.Current = string(hash) == string(currentHash)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *SQLiteStore) RevokeUserSession(userID, publicID string, event model.AuditEvent) error {
	return s.revokeSessions(`DELETE FROM sessions WHERE user_id=? AND public_id=?`, []any{userID, publicID}, event)
}

func (s *SQLiteStore) RevokeOtherUserSessions(userID string, currentHash []byte, event model.AuditEvent) error {
	return s.revokeSessions(`DELETE FROM sessions WHERE user_id=? AND id_hash<>?`, []any{userID, currentHash}, event)
}

func (s *SQLiteStore) revokeSessions(query string, args []any, event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin session revocation: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(query, args...); err != nil {
		return fmt.Errorf("revoke sessions: %w", err)
	}
	if err := insertAuditEvent(tx, event); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit session revocation: %w", err)
	}
	return nil
}

func (s *SQLiteStore) SessionUser(idHash []byte, now time.Time) (model.User, error) {
	var user model.User
	var created, updated, lastSeen string
	var lastLogin sql.NullString
	err := s.db.QueryRow(`SELECT u.id, u.email, u.display_name, u.role, u.status, u.mfa_required,
		u.created_at, u.updated_at, u.last_login_at, s.last_seen_at
		FROM sessions s JOIN users u ON u.id=s.user_id
		WHERE s.id_hash=? AND s.expires_at>? AND u.status='active'`, idHash, formatTime(now)).
		Scan(&user.ID, &user.Email, &user.DisplayName, &user.Role, &user.Status, &user.MFARequired,
			&created, &updated, &lastLogin, &lastSeen)
	if errors.Is(err, sql.ErrNoRows) {
		return model.User{}, ErrIdentityNotFound
	}
	if err != nil {
		return model.User{}, fmt.Errorf("load session user: %w", err)
	}
	if user.CreatedAt, err = parseTime(created); err != nil {
		return model.User{}, err
	}
	if user.UpdatedAt, err = parseTime(updated); err != nil {
		return model.User{}, err
	}
	if user.LastLoginAt, err = parseOptionalTime(lastLogin); err != nil {
		return model.User{}, err
	}
	seenAt, err := parseTime(lastSeen)
	if err != nil {
		return model.User{}, err
	}
	if now.Sub(seenAt) >= sessionTouchInterval {
		if _, err := s.db.Exec(`UPDATE sessions SET last_seen_at=? WHERE id_hash=?`, formatTime(now), idHash); err != nil {
			return model.User{}, fmt.Errorf("update session activity: %w", err)
		}
	}
	return user, nil
}

func (s *SQLiteStore) DeleteSession(idHash []byte, event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin session deletion: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM sessions WHERE id_hash=?`, idHash); err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	if err := insertAuditEvent(tx, event); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit session deletion: %w", err)
	}
	return nil
}

func (s *SQLiteStore) TOTPSecret(userID string) ([]byte, int64, error) {
	var ciphertext []byte
	var counter int64
	err := s.db.QueryRow(`SELECT secret_ciphertext, last_counter FROM totp_credentials WHERE user_id=?`, userID).
		Scan(&ciphertext, &counter)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, 0, ErrIdentityNotFound
	}
	if err != nil {
		return nil, 0, fmt.Errorf("load TOTP credential: %w", err)
	}
	return ciphertext, counter, nil
}

func (s *SQLiteStore) ConsumeTOTPCounter(userID string, counter int64) (bool, error) {
	result, err := s.db.Exec(`UPDATE totp_credentials SET last_counter=? WHERE user_id=? AND last_counter<?`, counter, userID, counter)
	if err != nil {
		return false, fmt.Errorf("consume TOTP counter: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("read TOTP counter result: %w", err)
	}
	return changed == 1, nil
}

func (s *SQLiteStore) ConsumeRecoveryCode(userID string, codeHash []byte, usedAt time.Time, event model.AuditEvent) (bool, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return false, fmt.Errorf("begin recovery code use: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.Exec(`UPDATE recovery_codes SET used_at=? WHERE user_id=? AND code_hash=? AND used_at IS NULL`,
		formatTime(usedAt), userID, codeHash)
	if err != nil {
		return false, fmt.Errorf("consume recovery code: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("read recovery code result: %w", err)
	}
	if changed != 1 {
		return false, nil
	}
	if err := insertAuditEvent(tx, event); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit recovery code use: %w", err)
	}
	return true, nil
}

func insertAuditEvent(tx *sql.Tx, event model.AuditEvent) error {
	_, err := tx.Exec(`INSERT INTO audit_events(occurred_at, actor_id, action, severity, target_type, target_id, source_ip, details)
		VALUES(?, NULLIF(?, ''), ?, ?, ?, ?, ?, ?)`, formatTime(event.OccurredAt), event.ActorID, event.Action,
		event.Severity, event.TargetType, event.TargetID, event.SourceIP, event.Details)
	if err != nil {
		return fmt.Errorf("insert audit event: %w", err)
	}
	return nil
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
