package store

import (
	"database/sql"
	"encoding/json"
	"errors"

	"mossward/internal/model"
)

func (s *SQLiteStore) SaveCoverageDiscoveryPolicy(policy model.CoverageDiscoveryPolicy, event model.AuditEvent) error {
	cidrs, err := json.Marshal(policy.CIDRs)
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var existingCreatedBy, existingCreatedAt string
	lookupErr := tx.QueryRow(`SELECT created_by,created_at FROM coverage_discovery_policies WHERE id=?`, policy.ID).Scan(&existingCreatedBy, &existingCreatedAt)
	switch {
	case errors.Is(lookupErr, sql.ErrNoRows) && policy.CreatedBy == "":
		return ErrNotFound
	case errors.Is(lookupErr, sql.ErrNoRows):
		_, err = tx.Exec(`INSERT INTO coverage_discovery_policies(id,name,cidrs,enabled,created_by,created_at,updated_by,updated_at) VALUES(?,?,?,?,?,?,?,?)`,
			policy.ID, policy.Name, cidrs, policy.Enabled, policy.CreatedBy, formatTime(policy.CreatedAt), policy.UpdatedBy, formatTime(policy.UpdatedAt))
	case lookupErr != nil:
		return lookupErr
	default:
		_, err = tx.Exec(`UPDATE coverage_discovery_policies SET name=?,cidrs=?,enabled=?,updated_by=?,updated_at=? WHERE id=?`,
			policy.Name, cidrs, policy.Enabled, policy.UpdatedBy, formatTime(policy.UpdatedAt), policy.ID)
	}
	if err != nil {
		return err
	}
	if err := insertAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLiteStore) ListCoverageDiscoveryPolicies() ([]model.CoverageDiscoveryPolicy, error) {
	rows, err := s.db.Query(`SELECT id,name,cidrs,enabled,created_by,created_at,updated_by,updated_at FROM coverage_discovery_policies ORDER BY name,id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	policies := []model.CoverageDiscoveryPolicy{}
	for rows.Next() {
		var policy model.CoverageDiscoveryPolicy
		var cidrs, createdAt, updatedAt string
		if err := rows.Scan(&policy.ID, &policy.Name, &cidrs, &policy.Enabled, &policy.CreatedBy, &createdAt, &policy.UpdatedBy, &updatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(cidrs), &policy.CIDRs); err != nil {
			return nil, err
		}
		policy.CreatedAt, _ = parseTime(createdAt)
		policy.UpdatedAt, _ = parseTime(updatedAt)
		policies = append(policies, policy)
	}
	return policies, rows.Err()
}
