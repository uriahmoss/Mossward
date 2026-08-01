package store

import (
	"database/sql"
	"errors"
	"fmt"

	"mossward/internal/model"
)

func (s *SQLiteStore) CreateAuthenticationCeremony(ceremony model.AuthenticationCeremony) error {
	var userID any
	if ceremony.UserID != "" {
		userID = ceremony.UserID
	}
	_, err := s.db.Exec(`INSERT INTO authentication_ceremonies(
		id_hash, user_id, kind, state_ciphertext, expires_at, created_at
	) VALUES(?, ?, ?, ?, ?, ?)`, ceremony.IDHash, userID, ceremony.Kind, ceremony.StateCiphertext,
		formatTime(ceremony.ExpiresAt), formatTime(ceremony.CreatedAt))
	if err != nil {
		return fmt.Errorf("create authentication ceremony: %w", err)
	}
	return nil
}

func (s *SQLiteStore) ConsumeAuthenticationCeremony(idHash []byte, kind model.AuthenticationCeremonyKind) (model.AuthenticationCeremony, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return model.AuthenticationCeremony{}, fmt.Errorf("begin authentication ceremony consumption: %w", err)
	}
	defer tx.Rollback()
	ceremony, err := loadAuthenticationCeremony(tx, idHash, kind)
	if err != nil {
		return model.AuthenticationCeremony{}, err
	}
	if _, err := tx.Exec(`DELETE FROM authentication_ceremonies WHERE id_hash=?`, idHash); err != nil {
		return model.AuthenticationCeremony{}, fmt.Errorf("consume authentication ceremony: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return model.AuthenticationCeremony{}, fmt.Errorf("commit authentication ceremony consumption: %w", err)
	}
	return ceremony, nil
}

func loadAuthenticationCeremony(tx *sql.Tx, idHash []byte, kind model.AuthenticationCeremonyKind) (model.AuthenticationCeremony, error) {
	var ceremony model.AuthenticationCeremony
	var userID sql.NullString
	var expiresAt, createdAt string
	err := tx.QueryRow(`SELECT id_hash, user_id, kind, state_ciphertext, expires_at, created_at
		FROM authentication_ceremonies WHERE id_hash=? AND kind=?`, idHash, kind).Scan(
		&ceremony.IDHash, &userID, &ceremony.Kind, &ceremony.StateCiphertext, &expiresAt, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.AuthenticationCeremony{}, ErrCeremonyNotFound
	}
	if err != nil {
		return model.AuthenticationCeremony{}, fmt.Errorf("load authentication ceremony: %w", err)
	}
	ceremony.UserID = userID.String
	if ceremony.ExpiresAt, err = parseTime(expiresAt); err != nil {
		return model.AuthenticationCeremony{}, err
	}
	if ceremony.CreatedAt, err = parseTime(createdAt); err != nil {
		return model.AuthenticationCeremony{}, err
	}
	return ceremony, nil
}
