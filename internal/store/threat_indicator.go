package store

import (
	"database/sql"
	"time"

	"mossward/internal/model"
)

func (s *SQLiteStore) UpsertThreatIndicator(indicator model.ThreatIndicator, now time.Time, event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO threat_indicators(id,type,value,source,confidence,observed_at,expires_at,enabled,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET type=excluded.type,value=excluded.value,source=excluded.source,confidence=excluded.confidence,observed_at=excluded.observed_at,expires_at=excluded.expires_at,enabled=excluded.enabled,updated_at=excluded.updated_at`,
		indicator.ID, indicator.Type, indicator.Value, indicator.Source, indicator.Confidence, formatTime(indicator.ObservedAt), formatTime(indicator.ExpiresAt), indicator.Enabled, indicator.CreatedBy, formatTime(indicator.CreatedAt), formatTime(indicator.UpdatedAt))
	if err != nil {
		return err
	}
	if err := refreshAllIndicatorMatches(tx, now); err != nil {
		return err
	}
	if err := insertAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLiteStore) ListThreatIndicators() ([]model.ThreatIndicator, error) {
	rows, err := s.db.Query(`SELECT id,type,value,source,confidence,observed_at,expires_at,enabled,created_by,created_at,updated_at FROM threat_indicators ORDER BY updated_at DESC,id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var indicators []model.ThreatIndicator
	for rows.Next() {
		var indicator model.ThreatIndicator
		var observedAt, expiresAt, createdAt, updatedAt string
		if err := rows.Scan(&indicator.ID, &indicator.Type, &indicator.Value, &indicator.Source, &indicator.Confidence, &observedAt, &expiresAt, &indicator.Enabled, &indicator.CreatedBy, &createdAt, &updatedAt); err != nil {
			return nil, err
		}
		indicator.ObservedAt, _ = parseTime(observedAt)
		indicator.ExpiresAt, _ = parseTime(expiresAt)
		indicator.CreatedAt, _ = parseTime(createdAt)
		indicator.UpdatedAt, _ = parseTime(updatedAt)
		indicators = append(indicators, indicator)
	}
	return indicators, rows.Err()
}

func (s *SQLiteStore) EndpointIndicatorMatches(endpointID string, now time.Time) ([]model.EndpointIndicatorMatch, error) {
	rows, err := s.db.Query(`SELECT m.endpoint_id,i.id,i.type,i.value,i.source,i.confidence,i.expires_at,c.remote_address,c.remote_hostname,c.process_name,c.executable,m.matched_at
		FROM endpoint_indicator_matches m JOIN threat_indicators i ON i.id=m.indicator_id JOIN endpoint_network_connections c ON c.endpoint_id=m.endpoint_id AND c.ordinal=m.connection_ordinal
		WHERE m.endpoint_id=? AND i.enabled=1 AND i.expires_at>? ORDER BY m.matched_at DESC,i.id,c.ordinal`, endpointID, formatTime(now))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var matches []model.EndpointIndicatorMatch
	for rows.Next() {
		var match model.EndpointIndicatorMatch
		var expiresAt, matchedAt string
		if err := rows.Scan(&match.EndpointID, &match.IndicatorID, &match.IndicatorType, &match.IndicatorValue, &match.Source, &match.Confidence, &expiresAt, &match.RemoteAddress, &match.RemoteHostname, &match.ProcessName, &match.Executable, &matchedAt); err != nil {
			return nil, err
		}
		match.ExpiresAt, _ = parseTime(expiresAt)
		match.MatchedAt, _ = parseTime(matchedAt)
		matches = append(matches, match)
	}
	return matches, rows.Err()
}

func refreshAllIndicatorMatches(tx *sql.Tx, now time.Time) error {
	rows, err := tx.Query(`SELECT endpoint_id FROM endpoint_network_inventory`)
	if err != nil {
		return err
	}
	var endpointIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		endpointIDs = append(endpointIDs, id)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, id := range endpointIDs {
		if err := refreshEndpointIndicatorMatches(tx, id, now); err != nil {
			return err
		}
	}
	return nil
}

func refreshEndpointIndicatorMatches(tx *sql.Tx, endpointID string, now time.Time) error {
	if _, err := tx.Exec(`DELETE FROM endpoint_indicator_matches WHERE endpoint_id=?`, endpointID); err != nil {
		return err
	}
	_, err := tx.Exec(`INSERT INTO endpoint_indicator_matches(endpoint_id,indicator_id,connection_ordinal,matched_at)
		SELECT c.endpoint_id,i.id,c.ordinal,? FROM endpoint_network_connections c JOIN threat_indicators i
		ON (i.type='ip' AND i.value=c.remote_address) OR (i.type='hostname' AND i.value=lower(rtrim(c.remote_hostname,'.')))
		WHERE c.endpoint_id=? AND i.enabled=1 AND i.observed_at<=? AND i.expires_at>?`, formatTime(now), endpointID, formatTime(now), formatTime(now))
	return err
}
