package store

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"mossward/internal/model"
)

func (s *PostgreSQLStore) CreateSession(session model.Session, event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL session creation: %w", err)
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO sessions(id_hash,public_id,user_id,created_at,expires_at,last_seen_at,mfa_verified_at,source_ip,user_agent_hash)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, session.IDHash, session.PublicID, session.UserID, session.CreatedAt.UTC(),
		session.ExpiresAt.UTC(), session.LastSeenAt.UTC(), session.MFAVerifiedAt, session.SourceIP, session.UserAgentHash)
	if err != nil {
		return fmt.Errorf("create PostgreSQL session: %w", err)
	}
	if _, err := tx.Exec(`UPDATE users SET last_login_at=$1,updated_at=$1 WHERE id=$2`, session.CreatedAt.UTC(), session.UserID); err != nil {
		return fmt.Errorf("update PostgreSQL last login: %w", err)
	}
	if err := insertPostgreSQLAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgreSQLStore) SessionUser(idHash []byte, now time.Time) (model.User, error) {
	var user model.User
	var lastLogin sql.NullTime
	err := s.db.QueryRow(`SELECT u.id,u.email,u.display_name,u.role,u.status,u.mfa_required,u.created_at,u.updated_at,u.last_login_at
		FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id_hash=$1 AND s.expires_at>$2 AND u.status='active'`, idHash, now.UTC()).
		Scan(&user.ID, &user.Email, &user.DisplayName, &user.Role, &user.Status, &user.MFARequired,
			&user.CreatedAt, &user.UpdatedAt, &lastLogin)
	if errors.Is(err, sql.ErrNoRows) {
		return model.User{}, ErrIdentityNotFound
	}
	if err != nil {
		return model.User{}, fmt.Errorf("load PostgreSQL session user: %w", err)
	}
	user.CreatedAt = user.CreatedAt.UTC()
	user.UpdatedAt = user.UpdatedAt.UTC()
	if lastLogin.Valid {
		value := lastLogin.Time.UTC()
		user.LastLoginAt = &value
	}
	if _, err := s.db.Exec(`UPDATE sessions SET last_seen_at=$1 WHERE id_hash=$2 AND last_seen_at<=$3`,
		now.UTC(), idHash, now.Add(-sessionTouchInterval).UTC()); err != nil {
		return model.User{}, fmt.Errorf("update PostgreSQL session activity: %w", err)
	}
	return user, nil
}

func (s *PostgreSQLStore) DeleteSession(idHash []byte, event model.AuditEvent) error {
	return s.revokeSessions(`DELETE FROM sessions WHERE id_hash=$1`, []any{idHash}, event)
}

func (s *PostgreSQLStore) ListUserSessions(userID string, currentHash []byte, now time.Time) ([]model.SessionInfo, error) {
	rows, err := s.db.Query(`SELECT public_id,created_at,expires_at,last_seen_at,mfa_verified_at,source_ip,id_hash
		FROM sessions WHERE user_id=$1 AND expires_at>$2 ORDER BY created_at DESC`, userID, now.UTC())
	if err != nil {
		return nil, fmt.Errorf("list PostgreSQL user sessions: %w", err)
	}
	defer rows.Close()
	items := []model.SessionInfo{}
	for rows.Next() {
		var item model.SessionInfo
		var mfa sql.NullTime
		var hash []byte
		if err := rows.Scan(&item.ID, &item.CreatedAt, &item.ExpiresAt, &item.LastSeenAt, &mfa, &item.SourceIP, &hash); err != nil {
			return nil, fmt.Errorf("scan PostgreSQL user session: %w", err)
		}
		item.CreatedAt = item.CreatedAt.UTC()
		item.ExpiresAt = item.ExpiresAt.UTC()
		item.LastSeenAt = item.LastSeenAt.UTC()
		if mfa.Valid {
			value := mfa.Time.UTC()
			item.MFAVerifiedAt = &value
		}
		item.Current = bytes.Equal(hash, currentHash)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PostgreSQLStore) RevokeUserSession(userID, publicID string, event model.AuditEvent) error {
	return s.revokeSessions(`DELETE FROM sessions WHERE user_id=$1 AND public_id=$2`, []any{userID, publicID}, event)
}

func (s *PostgreSQLStore) RevokeOtherUserSessions(userID string, currentHash []byte, event model.AuditEvent) error {
	return s.revokeSessions(`DELETE FROM sessions WHERE user_id=$1 AND id_hash<>$2`, []any{userID, currentHash}, event)
}

func (s *PostgreSQLStore) revokeSessions(query string, arguments []any, event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL session revocation: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(query, arguments...); err != nil {
		return fmt.Errorf("revoke PostgreSQL sessions: %w", err)
	}
	if err := insertPostgreSQLAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgreSQLStore) SessionMFAVerifiedAt(idHash []byte, userID string, now time.Time) (*time.Time, error) {
	var value sql.NullTime
	err := s.db.QueryRow(`SELECT mfa_verified_at FROM sessions WHERE id_hash=$1 AND user_id=$2 AND expires_at>$3`,
		idHash, userID, now.UTC()).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrIdentityNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("load PostgreSQL session MFA verification: %w", err)
	}
	if !value.Valid {
		return nil, nil
	}
	verifiedAt := value.Time.UTC()
	return &verifiedAt, nil
}

func (s *PostgreSQLStore) UpdateSessionMFAVerifiedAt(idHash []byte, userID string, verifiedAt time.Time) error {
	result, err := s.db.Exec(`UPDATE sessions SET mfa_verified_at=$1 WHERE id_hash=$2 AND user_id=$3`, verifiedAt.UTC(), idHash, userID)
	if err != nil {
		return fmt.Errorf("update PostgreSQL session MFA verification: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return ErrIdentityNotFound
	}
	return nil
}

func (s *PostgreSQLStore) AppendAuditEvent(event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL audit event: %w", err)
	}
	defer tx.Rollback()
	if err := insertPostgreSQLAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}
