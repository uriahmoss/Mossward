package store

import (
	"database/sql"
	"errors"
	"fmt"
	"math"
	"time"

	"mossward/internal/model"
)

func (s *PostgreSQLStore) RecordEndpointIntegritySnapshot(endpointID string, envelope model.SignedAgentIntegritySnapshot, receivedAt time.Time) error {
	if envelope.Sequence > math.MaxInt64 {
		return errors.New("endpoint integrity sequence exceeds the supported range")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL endpoint integrity snapshot: %w", err)
	}
	defer tx.Rollback()
	var status model.EndpointStatus
	err = tx.QueryRow(`SELECT status FROM endpoints WHERE id=$1 FOR UPDATE`, endpointID).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("lock PostgreSQL endpoint integrity identity: %w", err)
	}
	if status != model.EndpointActive {
		return ErrNotFound
	}
	previous, previousSequence, found, err := loadPostgreSQLIntegritySnapshot(tx, endpointID)
	if err != nil {
		return err
	}
	if found && envelope.Sequence <= uint64(previousSequence) {
		return ErrEndpointIntegrityReplay
	}
	if found {
		if err := recordPostgreSQLIntegrityChanges(tx, endpointID, previous, envelope, receivedAt); err != nil {
			return err
		}
	}
	snapshot := envelope.Snapshot
	_, err = tx.Exec(`INSERT INTO endpoint_integrity_snapshots(endpoint_id,executable_sha256,configuration_sha256,
		identity_sha256,observed_at,received_at,sequence,signature) VALUES($1,$2,$3,$4,$5,$6,$7,$8)
		ON CONFLICT(endpoint_id) DO UPDATE SET executable_sha256=EXCLUDED.executable_sha256,
		configuration_sha256=EXCLUDED.configuration_sha256,identity_sha256=EXCLUDED.identity_sha256,
		observed_at=EXCLUDED.observed_at,received_at=EXCLUDED.received_at,sequence=EXCLUDED.sequence,
		signature=EXCLUDED.signature`, endpointID, snapshot.ExecutableSHA256, snapshot.ConfigurationSHA256,
		snapshot.IdentitySHA256, snapshot.ObservedAt, receivedAt, int64(envelope.Sequence), envelope.Signature)
	if err != nil {
		return fmt.Errorf("record PostgreSQL endpoint integrity snapshot: %w", err)
	}
	return tx.Commit()
}

func loadPostgreSQLIntegritySnapshot(tx *sql.Tx, endpointID string) (model.AgentIntegritySnapshot, int64, bool, error) {
	var snapshot model.AgentIntegritySnapshot
	var sequence int64
	err := tx.QueryRow(`SELECT executable_sha256,configuration_sha256,identity_sha256,observed_at,sequence
		FROM endpoint_integrity_snapshots WHERE endpoint_id=$1`, endpointID).Scan(&snapshot.ExecutableSHA256,
		&snapshot.ConfigurationSHA256, &snapshot.IdentitySHA256, &snapshot.ObservedAt, &sequence)
	if errors.Is(err, sql.ErrNoRows) {
		return snapshot, 0, false, nil
	}
	if err != nil {
		return snapshot, 0, false, fmt.Errorf("load PostgreSQL endpoint integrity snapshot: %w", err)
	}
	return snapshot, sequence, true, nil
}

func recordPostgreSQLIntegrityChanges(tx *sql.Tx, endpointID string, previous model.AgentIntegritySnapshot,
	envelope model.SignedAgentIntegritySnapshot, receivedAt time.Time) error {
	snapshot := envelope.Snapshot
	changes := []struct{ component, before, after string }{
		{"executable", previous.ExecutableSHA256, snapshot.ExecutableSHA256},
		{"configuration", previous.ConfigurationSHA256, snapshot.ConfigurationSHA256},
		{"identity", previous.IdentitySHA256, snapshot.IdentitySHA256},
	}
	for _, change := range changes {
		if change.before == change.after {
			continue
		}
		_, err := tx.Exec(`INSERT INTO endpoint_integrity_events(endpoint_id,component,previous_sha256,current_sha256,
			observed_at,received_at,sequence,signature) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, endpointID,
			change.component, change.before, change.after, snapshot.ObservedAt, receivedAt, int64(envelope.Sequence), envelope.Signature)
		if err != nil {
			return fmt.Errorf("record PostgreSQL endpoint integrity event: %w", err)
		}
	}
	return nil
}

func (s *PostgreSQLStore) EndpointIntegrityEvents(endpointID string) ([]model.AgentIntegrityEvent, error) {
	rows, err := s.db.Query(`SELECT id,endpoint_id,component,previous_sha256,current_sha256,observed_at,received_at,
		sequence,signature FROM endpoint_integrity_events WHERE endpoint_id=$1 ORDER BY received_at DESC,id DESC`, endpointID)
	if err != nil {
		return nil, fmt.Errorf("load PostgreSQL endpoint integrity events: %w", err)
	}
	defer rows.Close()
	events := []model.AgentIntegrityEvent{}
	for rows.Next() {
		var event model.AgentIntegrityEvent
		var sequence int64
		if err := rows.Scan(&event.ID, &event.EndpointID, &event.Component, &event.PreviousSHA256,
			&event.CurrentSHA256, &event.ObservedAt, &event.ReceivedAt, &sequence, &event.Signature); err != nil {
			return nil, fmt.Errorf("read PostgreSQL endpoint integrity event: %w", err)
		}
		event.Sequence = uint64(sequence)
		events = append(events, event)
	}
	return events, rows.Err()
}
