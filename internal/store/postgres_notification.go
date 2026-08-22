package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"mossward/internal/model"
)

func (s *PostgreSQLStore) SMTPSettings() (model.SMTPSettings, error) {
	var settings model.SMTPSettings
	err := s.db.QueryRow(`SELECT enabled,host,port,username,password_ciphertext,from_address,tls_mode FROM smtp_settings WHERE id=1`).
		Scan(&settings.Enabled, &settings.Host, &settings.Port, &settings.Username, &settings.PasswordCiphertext, &settings.FromAddress, &settings.TLSMode)
	if errors.Is(err, sql.ErrNoRows) {
		return settings, nil
	}
	if err != nil {
		return settings, fmt.Errorf("load PostgreSQL SMTP settings: %w", err)
	}
	settings.HasPassword = len(settings.PasswordCiphertext) > 0
	rows, err := s.db.Query(`SELECT user_id FROM smtp_recipients ORDER BY user_id`)
	if err != nil {
		return settings, fmt.Errorf("list PostgreSQL SMTP recipients: %w", err)
	}
	defer rows.Close()
	settings.RecipientUserIDs = []string{}
	for rows.Next() {
		var userID string
		if err := rows.Scan(&userID); err != nil {
			return settings, fmt.Errorf("scan PostgreSQL SMTP recipient: %w", err)
		}
		settings.RecipientUserIDs = append(settings.RecipientUserIDs, userID)
	}
	return settings, rows.Err()
}

func (s *PostgreSQLStore) SaveSMTPSettings(settings model.SMTPSettings, event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL SMTP update: %w", err)
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO smtp_settings(id,enabled,host,port,username,password_ciphertext,from_address,tls_mode)
		VALUES(1,$1,$2,$3,$4,$5,$6,$7) ON CONFLICT(id) DO UPDATE SET enabled=EXCLUDED.enabled,host=EXCLUDED.host,
		port=EXCLUDED.port,username=EXCLUDED.username,password_ciphertext=EXCLUDED.password_ciphertext,
		from_address=EXCLUDED.from_address,tls_mode=EXCLUDED.tls_mode`, settings.Enabled, settings.Host, settings.Port,
		settings.Username, settings.PasswordCiphertext, settings.FromAddress, settings.TLSMode)
	if err != nil {
		return fmt.Errorf("store PostgreSQL SMTP settings: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM smtp_recipients`); err != nil {
		return fmt.Errorf("replace PostgreSQL SMTP recipients: %w", err)
	}
	for _, userID := range settings.RecipientUserIDs {
		if _, err := tx.Exec(`INSERT INTO smtp_recipients(user_id) VALUES($1)`, userID); err != nil {
			return fmt.Errorf("store PostgreSQL SMTP recipient: %w", err)
		}
	}
	if err := insertPostgreSQLAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgreSQLStore) MarkScanLongAlertSent(scanID string) error {
	_, err := s.db.Exec(`INSERT INTO scan_long_alerts(scan_id,sent_at) VALUES($1,$2) ON CONFLICT(scan_id) DO NOTHING`, scanID, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("mark PostgreSQL long-running scan alert: %w", err)
	}
	return nil
}
