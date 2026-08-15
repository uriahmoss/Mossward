package store

import (
	"database/sql"
	"errors"
	"time"

	"mossward/internal/model"
)

func (s *SQLiteStore) RecordEndpointIntegritySnapshot(endpointID string, snapshot model.AgentIntegritySnapshot, receivedAt time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var previous model.AgentIntegritySnapshot
	var previousObservedAt string
	lookupErr := tx.QueryRow(`SELECT executable_sha256,configuration_sha256,identity_sha256,observed_at FROM endpoint_integrity_snapshots WHERE endpoint_id=?`, endpointID).
		Scan(&previous.ExecutableSHA256, &previous.ConfigurationSHA256, &previous.IdentitySHA256, &previousObservedAt)
	if lookupErr != nil && !errors.Is(lookupErr, sql.ErrNoRows) {
		return lookupErr
	}
	if lookupErr == nil {
		previous.ObservedAt, _ = parseTime(previousObservedAt)
		if !snapshot.ObservedAt.After(previous.ObservedAt) {
			return nil
		}
		changes := []struct{ component, before, after string }{
			{"executable", previous.ExecutableSHA256, snapshot.ExecutableSHA256},
			{"configuration", previous.ConfigurationSHA256, snapshot.ConfigurationSHA256},
			{"identity", previous.IdentitySHA256, snapshot.IdentitySHA256},
		}
		for _, change := range changes {
			if change.before == change.after {
				continue
			}
			_, err := tx.Exec(`INSERT INTO endpoint_integrity_events(endpoint_id,component,previous_sha256,current_sha256,observed_at,received_at) VALUES(?,?,?,?,?,?)`,
				endpointID, change.component, change.before, change.after, formatTime(snapshot.ObservedAt), formatTime(receivedAt))
			if err != nil {
				return err
			}
		}
	}
	result, err := tx.Exec(`INSERT INTO endpoint_integrity_snapshots(endpoint_id,executable_sha256,configuration_sha256,identity_sha256,observed_at,received_at)
		SELECT id,?,?,?,?,? FROM endpoints WHERE id=? AND status='active' ON CONFLICT(endpoint_id) DO UPDATE SET executable_sha256=excluded.executable_sha256,configuration_sha256=excluded.configuration_sha256,identity_sha256=excluded.identity_sha256,observed_at=excluded.observed_at,received_at=excluded.received_at`,
		snapshot.ExecutableSHA256, snapshot.ConfigurationSHA256, snapshot.IdentitySHA256, formatTime(snapshot.ObservedAt), formatTime(receivedAt), endpointID)
	if err != nil {
		return err
	}
	changed, _ := result.RowsAffected()
	if changed != 1 {
		return ErrNotFound
	}
	return tx.Commit()
}

func (s *SQLiteStore) EndpointIntegrityEvents(endpointID string) ([]model.AgentIntegrityEvent, error) {
	rows, err := s.db.Query(`SELECT id,endpoint_id,component,previous_sha256,current_sha256,observed_at,received_at FROM endpoint_integrity_events WHERE endpoint_id=? ORDER BY received_at DESC,id DESC`, endpointID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events := []model.AgentIntegrityEvent{}
	for rows.Next() {
		var event model.AgentIntegrityEvent
		var observedAt, receivedAt string
		if err := rows.Scan(&event.ID, &event.EndpointID, &event.Component, &event.PreviousSHA256, &event.CurrentSHA256, &observedAt, &receivedAt); err != nil {
			return nil, err
		}
		event.ObservedAt, _ = parseTime(observedAt)
		event.ReceivedAt, _ = parseTime(receivedAt)
		events = append(events, event)
	}
	return events, rows.Err()
}
