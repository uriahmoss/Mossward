package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"mossward/internal/model"
)

func (s *PostgreSQLStore) RecordEndpointNetworkInventory(endpointID string, inventory model.EndpointNetworkInventory, receivedAt time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL endpoint network inventory: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.Exec(`INSERT INTO endpoint_network_inventory(endpoint_id,collected_at,received_at)
		SELECT id,$1,$2 FROM endpoints WHERE id=$3 AND status='active'
		ON CONFLICT(endpoint_id) DO UPDATE SET collected_at=EXCLUDED.collected_at,received_at=EXCLUDED.received_at`,
		inventory.CollectedAt, receivedAt, endpointID)
	if err != nil {
		return fmt.Errorf("record PostgreSQL endpoint network inventory: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return ErrNotFound
	}
	if _, err := tx.Exec(`DELETE FROM endpoint_network_connections WHERE endpoint_id=$1`, endpointID); err != nil {
		return fmt.Errorf("replace PostgreSQL endpoint network connections: %w", err)
	}
	for ordinal, connection := range inventory.Connections {
		_, err := tx.Exec(`INSERT INTO endpoint_network_connections(endpoint_id,ordinal,protocol,local_address,local_port,
			remote_address,remote_port,process_id,process_name,direction,executable,remote_hostname,hostname_source,tls_server_name)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, endpointID, ordinal, connection.Protocol,
			connection.LocalAddress, connection.LocalPort, connection.RemoteAddress, connection.RemotePort,
			connection.ProcessID, connection.ProcessName, connection.Direction, connection.Executable,
			connection.RemoteHostname, connection.HostnameSource, connection.TLSServerName)
		if err != nil {
			return fmt.Errorf("record PostgreSQL endpoint network connection: %w", err)
		}
	}
	if err := refreshPostgreSQLEndpointIndicatorMatches(tx, endpointID, receivedAt); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgreSQLStore) EndpointNetworkInventory(endpointID string) (model.EndpointNetworkInventory, error) {
	var inventory model.EndpointNetworkInventory
	err := s.db.QueryRow(`SELECT endpoint_id,collected_at,received_at FROM endpoint_network_inventory WHERE endpoint_id=$1`, endpointID).
		Scan(&inventory.EndpointID, &inventory.CollectedAt, &inventory.ReceivedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return inventory, ErrNotFound
	}
	if err != nil {
		return inventory, fmt.Errorf("load PostgreSQL endpoint network inventory: %w", err)
	}
	rows, err := s.db.Query(`SELECT protocol,local_address,local_port,remote_address,remote_port,process_id,process_name,
		direction,executable,remote_hostname,hostname_source,tls_server_name FROM endpoint_network_connections
		WHERE endpoint_id=$1 ORDER BY ordinal`, endpointID)
	if err != nil {
		return inventory, fmt.Errorf("load PostgreSQL endpoint network connections: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var connection model.NetworkConnection
		if err := rows.Scan(&connection.Protocol, &connection.LocalAddress, &connection.LocalPort,
			&connection.RemoteAddress, &connection.RemotePort, &connection.ProcessID, &connection.ProcessName,
			&connection.Direction, &connection.Executable, &connection.RemoteHostname, &connection.HostnameSource,
			&connection.TLSServerName); err != nil {
			return inventory, fmt.Errorf("read PostgreSQL endpoint network connection: %w", err)
		}
		inventory.Connections = append(inventory.Connections, connection)
	}
	return inventory, rows.Err()
}

func (s *PostgreSQLStore) UpsertThreatIndicator(indicator model.ThreatIndicator, now time.Time, event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL threat-indicator update: %w", err)
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO threat_indicators(id,type,value,source,confidence,observed_at,expires_at,enabled,
		created_by,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		ON CONFLICT(id) DO UPDATE SET type=EXCLUDED.type,value=EXCLUDED.value,source=EXCLUDED.source,
		confidence=EXCLUDED.confidence,observed_at=EXCLUDED.observed_at,expires_at=EXCLUDED.expires_at,
		enabled=EXCLUDED.enabled,updated_at=EXCLUDED.updated_at`, indicator.ID, indicator.Type, indicator.Value,
		indicator.Source, indicator.Confidence, indicator.ObservedAt, indicator.ExpiresAt, indicator.Enabled,
		indicator.CreatedBy, indicator.CreatedAt, indicator.UpdatedAt)
	if err != nil {
		return fmt.Errorf("save PostgreSQL threat indicator: %w", err)
	}
	if err := refreshAllPostgreSQLEndpointIndicatorMatches(tx, now); err != nil {
		return err
	}
	if err := insertPostgreSQLAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgreSQLStore) ListThreatIndicators() ([]model.ThreatIndicator, error) {
	rows, err := s.db.Query(`SELECT id,type,value,source,confidence,observed_at,expires_at,enabled,created_by,created_at,updated_at
		FROM threat_indicators ORDER BY updated_at DESC,id`)
	if err != nil {
		return nil, fmt.Errorf("list PostgreSQL threat indicators: %w", err)
	}
	defer rows.Close()
	indicators := []model.ThreatIndicator{}
	for rows.Next() {
		var indicator model.ThreatIndicator
		if err := rows.Scan(&indicator.ID, &indicator.Type, &indicator.Value, &indicator.Source, &indicator.Confidence,
			&indicator.ObservedAt, &indicator.ExpiresAt, &indicator.Enabled, &indicator.CreatedBy,
			&indicator.CreatedAt, &indicator.UpdatedAt); err != nil {
			return nil, fmt.Errorf("read PostgreSQL threat indicator: %w", err)
		}
		indicators = append(indicators, indicator)
	}
	return indicators, rows.Err()
}

func (s *PostgreSQLStore) EndpointIndicatorMatches(endpointID string, now time.Time) ([]model.EndpointIndicatorMatch, error) {
	rows, err := s.db.Query(`SELECT m.endpoint_id,i.id,i.type,i.value,i.source,i.confidence,i.expires_at,
		c.remote_address,c.remote_hostname,c.process_name,c.executable,m.matched_at
		FROM endpoint_indicator_matches m JOIN threat_indicators i ON i.id=m.indicator_id
		JOIN endpoint_network_connections c ON c.endpoint_id=m.endpoint_id AND c.ordinal=m.connection_ordinal
		WHERE m.endpoint_id=$1 AND i.enabled=TRUE AND i.expires_at>$2 ORDER BY m.matched_at DESC,i.id,c.ordinal`,
		endpointID, now)
	if err != nil {
		return nil, fmt.Errorf("load PostgreSQL endpoint indicator matches: %w", err)
	}
	defer rows.Close()
	matches := []model.EndpointIndicatorMatch{}
	for rows.Next() {
		var match model.EndpointIndicatorMatch
		if err := rows.Scan(&match.EndpointID, &match.IndicatorID, &match.IndicatorType, &match.IndicatorValue,
			&match.Source, &match.Confidence, &match.ExpiresAt, &match.RemoteAddress, &match.RemoteHostname,
			&match.ProcessName, &match.Executable, &match.MatchedAt); err != nil {
			return nil, fmt.Errorf("read PostgreSQL endpoint indicator match: %w", err)
		}
		matches = append(matches, match)
	}
	return matches, rows.Err()
}

func refreshAllPostgreSQLEndpointIndicatorMatches(tx *sql.Tx, now time.Time) error {
	rows, err := tx.Query(`SELECT endpoint_id FROM endpoint_network_inventory`)
	if err != nil {
		return fmt.Errorf("list PostgreSQL network inventories for indicator refresh: %w", err)
	}
	endpointIDs := []string{}
	for rows.Next() {
		var endpointID string
		if err := rows.Scan(&endpointID); err != nil {
			_ = rows.Close()
			return err
		}
		endpointIDs = append(endpointIDs, endpointID)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, endpointID := range endpointIDs {
		if err := refreshPostgreSQLEndpointIndicatorMatches(tx, endpointID, now); err != nil {
			return err
		}
	}
	return nil
}

func refreshPostgreSQLEndpointIndicatorMatches(tx *sql.Tx, endpointID string, now time.Time) error {
	if _, err := tx.Exec(`DELETE FROM endpoint_indicator_matches WHERE endpoint_id=$1`, endpointID); err != nil {
		return fmt.Errorf("replace PostgreSQL endpoint indicator matches: %w", err)
	}
	_, err := tx.Exec(`INSERT INTO endpoint_indicator_matches(endpoint_id,indicator_id,connection_ordinal,matched_at)
		SELECT c.endpoint_id,i.id,c.ordinal,$1 FROM endpoint_network_connections c JOIN threat_indicators i
		ON (i.type='ip' AND i.value=c.remote_address)
			OR (i.type='hostname' AND i.value=LOWER(RTRIM(c.remote_hostname,'.')))
		WHERE c.endpoint_id=$2 AND i.enabled=TRUE AND i.observed_at<=$1 AND i.expires_at>$1`, now, endpointID)
	if err != nil {
		return fmt.Errorf("refresh PostgreSQL endpoint indicator matches: %w", err)
	}
	return nil
}
