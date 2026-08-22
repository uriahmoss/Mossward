package store

import (
	"database/sql"
	"errors"
	"fmt"

	"mossward/internal/model"
)

func (s *PostgreSQLStore) Organization() (model.Organization, error) {
	var organization model.Organization
	err := s.db.QueryRow(`SELECT id,name,created_at FROM installation_organization WHERE singleton=TRUE`).
		Scan(&organization.ID, &organization.Name, &organization.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return organization, ErrOrganizationBoundary
	}
	if err != nil {
		return organization, fmt.Errorf("read PostgreSQL installation organization: %w", err)
	}
	return organization, nil
}

func (s *PostgreSQLStore) RequireOrganization(id string) error {
	organization, err := s.Organization()
	if err != nil {
		return err
	}
	if id == "" || id != organization.ID {
		return ErrOrganizationBoundary
	}
	return nil
}

func (s *PostgreSQLStore) EnsureDefaultScopePolicy(policy model.ScopePolicy) error {
	organization, err := s.Organization()
	if err != nil {
		return err
	}
	cidrs, ports, err := encodeScopePolicyLists(policy)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO scope_policies(id,organization_id,name,allowed_cidrs,allowed_ports,max_targets,max_concurrent,enabled,created_at,updated_at)
		SELECT $1,$2,$3,$4::jsonb,$5::jsonb,$6,$7,TRUE,$8,$9 WHERE NOT EXISTS(SELECT 1 FROM scope_policies WHERE organization_id=$2)`,
		policy.ID, organization.ID, policy.Name, string(cidrs), string(ports), policy.MaxTargets, policy.MaxConcurrent, policy.CreatedAt, policy.UpdatedAt)
	if err != nil {
		return fmt.Errorf("create default PostgreSQL scope policy: %w", err)
	}
	return nil
}

func (s *PostgreSQLStore) UpsertScopePolicy(policy model.ScopePolicy, event model.AuditEvent) error {
	organization, err := s.Organization()
	if err != nil {
		return err
	}
	cidrs, ports, err := encodeScopePolicyLists(policy)
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL scope-policy update: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.Exec(`INSERT INTO scope_policies(id,organization_id,name,allowed_cidrs,allowed_ports,max_targets,max_concurrent,enabled,created_by,created_at,updated_at)
		VALUES($1,$2,$3,$4::jsonb,$5::jsonb,$6,$7,$8,NULLIF($9,''),$10,$11)
		ON CONFLICT(id) DO UPDATE SET name=EXCLUDED.name,allowed_cidrs=EXCLUDED.allowed_cidrs,allowed_ports=EXCLUDED.allowed_ports,
		max_targets=EXCLUDED.max_targets,max_concurrent=EXCLUDED.max_concurrent,enabled=EXCLUDED.enabled,updated_at=EXCLUDED.updated_at
		WHERE scope_policies.organization_id=EXCLUDED.organization_id`, policy.ID, organization.ID, policy.Name, string(cidrs), string(ports),
		policy.MaxTargets, policy.MaxConcurrent, policy.Enabled, policy.CreatedBy, policy.CreatedAt, policy.UpdatedAt)
	if err != nil {
		return fmt.Errorf("store PostgreSQL scope policy: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return ErrOrganizationBoundary
	}
	if err := insertPostgreSQLAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgreSQLStore) ScopePolicy(id string) (model.ScopePolicy, error) {
	policy, err := scanPostgreSQLScopePolicy(s.db.QueryRow(postgresScopePolicySelect+` AND id=$1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return model.ScopePolicy{}, ErrNotFound
	}
	return policy, err
}

func (s *PostgreSQLStore) ListScopePolicies(enabledOnly bool) ([]model.ScopePolicy, error) {
	query := postgresScopePolicySelect
	if enabledOnly {
		query += ` AND enabled=TRUE`
	}
	rows, err := s.db.Query(query + ` ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list PostgreSQL scope policies: %w", err)
	}
	defer rows.Close()
	policies := []model.ScopePolicy{}
	for rows.Next() {
		policy, err := scanPostgreSQLScopePolicy(rows)
		if err != nil {
			return nil, err
		}
		policies = append(policies, policy)
	}
	return policies, rows.Err()
}

const postgresScopePolicySelect = `SELECT id,name,allowed_cidrs,allowed_ports,max_targets,max_concurrent,enabled,
	COALESCE(created_by,''),created_at,updated_at,organization_id FROM scope_policies
	WHERE organization_id=(SELECT id FROM installation_organization WHERE singleton=TRUE)`

func scanPostgreSQLScopePolicy(scanner interface{ Scan(...any) error }) (model.ScopePolicy, error) {
	var policy model.ScopePolicy
	var cidrs, ports []byte
	err := scanner.Scan(&policy.ID, &policy.Name, &cidrs, &ports, &policy.MaxTargets, &policy.MaxConcurrent,
		&policy.Enabled, &policy.CreatedBy, &policy.CreatedAt, &policy.UpdatedAt, &policy.OrganizationID)
	if err != nil {
		return policy, err
	}
	if err := decodeScopePolicyLists(&policy, cidrs, ports); err != nil {
		return model.ScopePolicy{}, err
	}
	return policy, nil
}

func insertPostgreSQLAuditEvent(tx *sql.Tx, event model.AuditEvent) error {
	details := event.Details
	if details == "" {
		details = "{}"
	}
	_, err := tx.Exec(`INSERT INTO audit_events(occurred_at,actor_id,action,severity,target_type,target_id,source_ip,details)
		VALUES($1,NULLIF($2,''),$3,$4,$5,$6,$7,$8::jsonb)`, event.OccurredAt, event.ActorID, event.Action,
		event.Severity, event.TargetType, event.TargetID, event.SourceIP, details)
	if err != nil {
		return fmt.Errorf("insert PostgreSQL audit event: %w", err)
	}
	return nil
}
