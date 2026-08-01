package store

import (
	"database/sql"
	"errors"
	"mossward/internal/model"
	"time"
)

func (s *SQLiteStore) SMTPSettings() (model.SMTPSettings, error) {
	var value model.SMTPSettings
	err := s.db.QueryRow(`SELECT enabled,host,port,username,password_ciphertext,from_address,tls_mode FROM smtp_settings WHERE id=1`).Scan(&value.Enabled, &value.Host, &value.Port, &value.Username, &value.PasswordCiphertext, &value.FromAddress, &value.TLSMode)
	if errors.Is(err, sql.ErrNoRows) {
		return value, nil
	}
	if err != nil {
		return value, err
	}
	value.HasPassword = len(value.PasswordCiphertext) > 0
	rows, err := s.db.Query(`SELECT user_id FROM smtp_recipients ORDER BY user_id`)
	if err != nil {
		return value, err
	}
	defer rows.Close()
	value.RecipientUserIDs = []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return value, err
		}
		value.RecipientUserIDs = append(value.RecipientUserIDs, id)
	}
	err = rows.Err()
	return value, err
}
func (s *SQLiteStore) SaveSMTPSettings(value model.SMTPSettings, event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO smtp_settings(id,enabled,host,port,username,password_ciphertext,from_address,tls_mode)VALUES(1,?,?,?,?,?,?,?) ON CONFLICT(id)DO UPDATE SET enabled=excluded.enabled,host=excluded.host,port=excluded.port,username=excluded.username,password_ciphertext=excluded.password_ciphertext,from_address=excluded.from_address,tls_mode=excluded.tls_mode`, value.Enabled, value.Host, value.Port, value.Username, value.PasswordCiphertext, value.FromAddress, value.TLSMode)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM smtp_recipients`); err != nil {
		return err
	}
	for _, id := range value.RecipientUserIDs {
		if _, err := tx.Exec(`INSERT INTO smtp_recipients(user_id)VALUES(?)`, id); err != nil {
			return err
		}
	}
	if err := insertAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *SQLiteStore) MarkScanLongAlertSent(id string) error {
	_, err := s.db.Exec(`INSERT INTO scan_long_alerts(scan_id,sent_at) VALUES(?,?) ON CONFLICT(scan_id) DO NOTHING`, id, formatTime(time.Now().UTC()))
	return err
}
