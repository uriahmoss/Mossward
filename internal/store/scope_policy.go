package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"mossward/internal/model"
)

func (s *SQLiteStore) EnsureDefaultScopePolicy(policy model.ScopePolicy) error {
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM scope_policies WHERE organization_id=(SELECT id FROM installation_organization WHERE singleton=1)`).Scan(&count); err != nil {
		return fmt.Errorf("count scope policies: %w", err)
	}
	if count > 0 {
		return nil
	}
	cidrs, ports, err := encodeScopePolicyLists(policy)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO scope_policies(id, name, allowed_cidrs, allowed_ports, max_targets,
		max_concurrent, enabled, created_by, created_at, updated_at, organization_id) VALUES(?, ?, ?, ?, ?, ?, 1, NULL, ?, ?, (SELECT id FROM installation_organization WHERE singleton=1))`,
		policy.ID, policy.Name, cidrs, ports, policy.MaxTargets, policy.MaxConcurrent,
		formatTime(policy.CreatedAt), formatTime(policy.UpdatedAt))
	if err != nil {
		return fmt.Errorf("create default scope policy: %w", err)
	}
	return nil
}

func (s *SQLiteStore) UpsertScopePolicy(policy model.ScopePolicy, event model.AuditEvent) error {
	cidrs, ports, err := encodeScopePolicyLists(policy)
	if err != nil {
		return err
	}
	var createdBy any
	if policy.CreatedBy != "" {
		createdBy = policy.CreatedBy
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin scope-policy update: %w", err)
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO scope_policies(id, name, allowed_cidrs, allowed_ports, max_targets,
		max_concurrent, enabled, created_by, created_at, updated_at, organization_id) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, (SELECT id FROM installation_organization WHERE singleton=1))
		ON CONFLICT(id) DO UPDATE SET name=excluded.name, allowed_cidrs=excluded.allowed_cidrs,
		allowed_ports=excluded.allowed_ports, max_targets=excluded.max_targets,
		max_concurrent=excluded.max_concurrent, enabled=excluded.enabled, updated_at=excluded.updated_at`,
		policy.ID, policy.Name, cidrs, ports, policy.MaxTargets, policy.MaxConcurrent, policy.Enabled,
		createdBy, formatTime(policy.CreatedAt), formatTime(policy.UpdatedAt))
	if err != nil {
		return fmt.Errorf("store scope policy: %w", err)
	}
	if err := insertAuditEvent(tx, event); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit scope-policy update: %w", err)
	}
	return nil
}

func (s *SQLiteStore) ScopePolicy(id string) (model.ScopePolicy, error) {
	policy, err := scanScopePolicy(s.db.QueryRow(scopePolicySelect+` AND id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return model.ScopePolicy{}, ErrNotFound
	}
	return policy, err
}

func (s *SQLiteStore) ListScopePolicies(enabledOnly bool) ([]model.ScopePolicy, error) {
	query := scopePolicySelect
	if enabledOnly {
		query += ` AND enabled=1`
	}
	rows, err := s.db.Query(query + ` ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list scope policies: %w", err)
	}
	defer rows.Close()
	items := []model.ScopePolicy{}
	for rows.Next() {
		item, err := scanScopePolicy(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

const scopePolicySelect = `SELECT id, name, allowed_cidrs, allowed_ports, max_targets, max_concurrent,
	enabled, COALESCE(created_by,''), created_at, updated_at, organization_id FROM scope_policies
	WHERE organization_id=(SELECT id FROM installation_organization WHERE singleton=1)`

func scanScopePolicy(scanner interface{ Scan(...any) error }) (model.ScopePolicy, error) {
	var policy model.ScopePolicy
	var cidrs, ports, createdAt, updatedAt string
	err := scanner.Scan(&policy.ID, &policy.Name, &cidrs, &ports, &policy.MaxTargets, &policy.MaxConcurrent,
		&policy.Enabled, &policy.CreatedBy, &createdAt, &updatedAt, &policy.OrganizationID)
	if err != nil {
		return model.ScopePolicy{}, err
	}
	if err := decodeScopePolicyLists(&policy, []byte(cidrs), []byte(ports)); err != nil {
		return model.ScopePolicy{}, err
	}
	if policy.CreatedAt, err = parseTime(createdAt); err != nil {
		return model.ScopePolicy{}, err
	}
	if policy.UpdatedAt, err = parseTime(updatedAt); err != nil {
		return model.ScopePolicy{}, err
	}
	return policy, nil
}

func decodeScopePolicyLists(policy *model.ScopePolicy, cidrs, ports []byte) error {
	if err := json.Unmarshal(cidrs, &policy.AllowedCIDRs); err != nil {
		return fmt.Errorf("decode scope-policy CIDRs: %w", err)
	}
	if err := json.Unmarshal(ports, &policy.AllowedPorts); err != nil {
		return fmt.Errorf("decode scope-policy ports: %w", err)
	}
	return nil
}

func encodeScopePolicyLists(policy model.ScopePolicy) ([]byte, []byte, error) {
	cidrs, err := json.Marshal(policy.AllowedCIDRs)
	if err != nil {
		return nil, nil, fmt.Errorf("encode scope-policy CIDRs: %w", err)
	}
	ports, err := json.Marshal(policy.AllowedPorts)
	if err != nil {
		return nil, nil, fmt.Errorf("encode scope-policy ports: %w", err)
	}
	return cidrs, ports, nil
}
