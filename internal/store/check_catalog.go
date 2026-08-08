package store

import (
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"mossward/internal/checkcatalog"
)

func (s *SQLiteStore) SavePublisher(value checkcatalog.Publisher) error {
	_, err := s.db.Exec(`INSERT INTO check_publishers(key_id,name,public_key,status,added_at,revoked_at) VALUES(?,?,?,?,?,NULL)
		ON CONFLICT(key_id) DO UPDATE SET name=excluded.name,status='trusted',revoked_at=NULL`,
		value.KeyID, value.Name, []byte(value.PublicKey), value.Status, formatTime(value.AddedAt))
	if err != nil {
		return fmt.Errorf("save check publisher: %w", err)
	}
	return nil
}

func (s *SQLiteStore) Publisher(keyID string) (checkcatalog.Publisher, error) {
	var value checkcatalog.Publisher
	var key []byte
	var added string
	var revoked sql.NullString
	err := s.db.QueryRow(`SELECT key_id,name,public_key,status,added_at,revoked_at FROM check_publishers WHERE key_id=?`, keyID).
		Scan(&value.KeyID, &value.Name, &key, &value.Status, &added, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return value, checkcatalog.ErrPublisherNotTrusted
	}
	if err != nil {
		return value, fmt.Errorf("load check publisher: %w", err)
	}
	value.PublicKey = ed25519.PublicKey(key)
	value.AddedAt, _ = parseTime(added)
	if revoked.Valid {
		parsed, _ := parseTime(revoked.String)
		value.RevokedAt = &parsed
	}
	return value, nil
}

func (s *SQLiteStore) RevokePublisher(keyID string, at time.Time) error {
	result, err := s.db.Exec(`UPDATE check_publishers SET status='revoked',revoked_at=? WHERE key_id=?`, formatTime(at), keyID)
	if err != nil {
		return fmt.Errorf("revoke check publisher: %w", err)
	}
	changed, _ := result.RowsAffected()
	if changed == 0 {
		return checkcatalog.ErrPublisherNotTrusted
	}
	return nil
}

func (s *SQLiteStore) SaveVersion(value checkcatalog.Version) error {
	encoded, err := json.Marshal(value.Envelope)
	if err != nil {
		return fmt.Errorf("encode check version: %w", err)
	}
	_, err = s.db.Exec(`INSERT INTO declarative_check_versions(check_id,version,kind,key_id,envelope_json,status,imported_at) VALUES(?,?,?,?,?,?,?)`,
		value.Envelope.Check.ID, value.Envelope.Check.Version, value.Envelope.Check.Kind, value.Envelope.KeyID, encoded, value.Status, formatTime(value.ImportedAt))
	if err != nil {
		return fmt.Errorf("save check version: %w", err)
	}
	return nil
}

func (s *SQLiteStore) Version(id, version string) (checkcatalog.Version, error) {
	return s.checkVersion(`SELECT envelope_json,status,imported_at,activated_at FROM declarative_check_versions WHERE check_id=? AND version=?`, id, version)
}

func (s *SQLiteStore) ActiveVersion(id string) (checkcatalog.Version, error) {
	return s.checkVersion(`SELECT envelope_json,status,imported_at,activated_at FROM declarative_check_versions WHERE check_id=? AND status='active'`, id)
}

func (s *SQLiteStore) checkVersion(query string, args ...any) (checkcatalog.Version, error) {
	var value checkcatalog.Version
	var encoded []byte
	var imported string
	var activated sql.NullString
	err := s.db.QueryRow(query, args...).Scan(&encoded, &value.Status, &imported, &activated)
	if errors.Is(err, sql.ErrNoRows) {
		return value, checkcatalog.ErrVersionNotFound
	}
	if err != nil {
		return value, fmt.Errorf("load check version: %w", err)
	}
	if err := json.Unmarshal(encoded, &value.Envelope); err != nil {
		return value, fmt.Errorf("decode check version: %w", err)
	}
	value.ImportedAt, _ = parseTime(imported)
	if activated.Valid {
		parsed, _ := parseTime(activated.String)
		value.ActivatedAt = &parsed
	}
	return value, nil
}

func (s *SQLiteStore) ActivateVersion(id, version string, at time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin check activation: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE declarative_check_versions SET status='retired' WHERE check_id=? AND status='active'`, id); err != nil {
		return fmt.Errorf("retire check version: %w", err)
	}
	result, err := tx.Exec(`UPDATE declarative_check_versions SET status='active',activated_at=? WHERE check_id=? AND version=?`, formatTime(at), id, version)
	if err != nil {
		return fmt.Errorf("activate check version: %w", err)
	}
	changed, _ := result.RowsAffected()
	if changed == 0 {
		return checkcatalog.ErrVersionNotFound
	}
	return tx.Commit()
}

var _ checkcatalog.Repository = (*SQLiteStore)(nil)
