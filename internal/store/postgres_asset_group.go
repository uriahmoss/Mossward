package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"mossward/internal/model"
)

func (s *PostgreSQLStore) UpsertAssetGroup(group model.AssetGroup, event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL asset-group update: %w", err)
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO asset_groups(id,name,description,created_at,updated_at) VALUES($1,$2,$3,$4,$5)
		ON CONFLICT(id) DO UPDATE SET name=EXCLUDED.name,description=EXCLUDED.description,updated_at=EXCLUDED.updated_at`,
		group.ID, group.Name, group.Description, group.CreatedAt, group.UpdatedAt)
	if err != nil {
		return fmt.Errorf("save PostgreSQL asset group: %w", err)
	}
	if err := insertPostgreSQLAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgreSQLStore) ListAssetGroups() ([]model.AssetGroup, error) {
	rows, err := s.db.Query(`SELECT id,name,description,created_at,updated_at FROM asset_groups ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list PostgreSQL asset groups: %w", err)
	}
	groups := []model.AssetGroup{}
	for rows.Next() {
		var group model.AssetGroup
		if err := rows.Scan(&group.ID, &group.Name, &group.Description, &group.CreatedAt, &group.UpdatedAt); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("read PostgreSQL asset group: %w", err)
		}
		groups = append(groups, group)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for index := range groups {
		groups[index].AssetIDs, err = s.postgreSQLStringColumn(
			`SELECT asset_id FROM asset_group_members WHERE group_id=$1 ORDER BY asset_id`, groups[index].ID)
		if err != nil {
			return nil, err
		}
		groups[index].ScanPolicyIDs, err = s.postgreSQLStringColumn(
			`SELECT scan_policy_id FROM reusable_scan_policy_groups WHERE group_id=$1 ORDER BY scan_policy_id`, groups[index].ID)
		if err != nil {
			return nil, err
		}
	}
	return groups, nil
}

func (s *PostgreSQLStore) postgreSQLStringColumn(query, value string) ([]string, error) {
	rows, err := s.db.Query(query, value)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := []string{}
	for rows.Next() {
		var item string
		if err := rows.Scan(&item); err != nil {
			return nil, err
		}
		values = append(values, item)
	}
	return values, rows.Err()
}

func (s *PostgreSQLStore) AssetGroupMemberships(assetID string) ([]string, error) {
	return s.postgreSQLStringColumn(`SELECT group_id FROM asset_group_members WHERE asset_id=$1 ORDER BY group_id`, assetID)
}

func (s *PostgreSQLStore) AddAssetGroupMember(groupID, assetID, actorID string, addedAt time.Time, event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL asset-group membership update: %w", err)
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO asset_group_members(group_id,asset_id,added_at,added_by) VALUES($1,$2,$3,$4)
		ON CONFLICT(group_id,asset_id) DO NOTHING`, groupID, assetID, addedAt, actorID)
	if err != nil {
		return fmt.Errorf("add PostgreSQL asset-group member: %w", err)
	}
	if err := insertPostgreSQLAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgreSQLStore) RemoveAssetGroupMember(groupID, assetID string, event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL asset-group membership removal: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.Exec(`DELETE FROM asset_group_members WHERE group_id=$1 AND asset_id=$2`, groupID, assetID)
	if err != nil {
		return fmt.Errorf("remove PostgreSQL asset-group member: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return ErrNotFound
	}
	if err := insertPostgreSQLAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgreSQLStore) UpsertReusableScanPolicy(policy model.ReusableScanPolicy, event model.AuditEvent) error {
	if policy.ExecutionMode == "" {
		policy.ExecutionMode = model.ScanExecutionLocal
	}
	ports, err := json.Marshal(policy.Ports)
	if err != nil {
		return fmt.Errorf("encode PostgreSQL reusable-policy ports: %w", err)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL reusable-policy update: %w", err)
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO reusable_scan_policies(id,name,scope_policy_id,ports,enabled,created_at,updated_at,
		schedule_kind,schedule_expression,schedule_timezone,window_start,window_end,run_missed,long_run_alert_seconds,
		next_run_at,last_scheduled_at,rate_limit_per_second,execution_mode,worker_site_id)
		VALUES($1,$2,$3,$4::jsonb,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
		ON CONFLICT(id) DO UPDATE SET name=EXCLUDED.name,scope_policy_id=EXCLUDED.scope_policy_id,ports=EXCLUDED.ports,
		enabled=EXCLUDED.enabled,updated_at=EXCLUDED.updated_at,schedule_kind=EXCLUDED.schedule_kind,
		schedule_expression=EXCLUDED.schedule_expression,schedule_timezone=EXCLUDED.schedule_timezone,
		window_start=EXCLUDED.window_start,window_end=EXCLUDED.window_end,run_missed=EXCLUDED.run_missed,
		long_run_alert_seconds=EXCLUDED.long_run_alert_seconds,next_run_at=EXCLUDED.next_run_at,
		last_scheduled_at=EXCLUDED.last_scheduled_at,rate_limit_per_second=EXCLUDED.rate_limit_per_second,
		execution_mode=EXCLUDED.execution_mode,worker_site_id=EXCLUDED.worker_site_id`, policy.ID, policy.Name,
		policy.ScopePolicyID, string(ports), policy.Enabled, policy.CreatedAt, policy.UpdatedAt, policy.ScheduleKind,
		policy.ScheduleExpression, policy.ScheduleTimezone, policy.WindowStart, policy.WindowEnd, policy.RunMissed,
		policy.LongRunAlertSeconds, policy.NextRunAt, policy.LastScheduledAt, policy.RateLimitPerSecond,
		policy.ExecutionMode, policy.WorkerSiteID)
	if err != nil {
		return fmt.Errorf("save PostgreSQL reusable scan policy: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM reusable_scan_policy_groups WHERE scan_policy_id=$1`, policy.ID); err != nil {
		return fmt.Errorf("replace PostgreSQL reusable-policy groups: %w", err)
	}
	for ordinal, groupID := range policy.GroupIDs {
		if _, err := tx.Exec(`INSERT INTO reusable_scan_policy_groups(scan_policy_id,group_id,ordinal) VALUES($1,$2,$3)`,
			policy.ID, groupID, ordinal); err != nil {
			return fmt.Errorf("save PostgreSQL reusable-policy group: %w", err)
		}
	}
	if err := insertPostgreSQLAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

const postgresReusablePolicySelect = `SELECT id,name,scope_policy_id,ports,enabled,created_at,updated_at,
	schedule_kind,schedule_expression,schedule_timezone,window_start,window_end,run_missed,long_run_alert_seconds,
	next_run_at,last_scheduled_at,rate_limit_per_second,execution_mode,worker_site_id FROM reusable_scan_policies`

func (s *PostgreSQLStore) ReusableScanPolicy(id string) (model.ReusableScanPolicy, error) {
	policy, err := scanPostgreSQLReusablePolicy(s.db.QueryRow(postgresReusablePolicySelect+` WHERE id=$1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return model.ReusableScanPolicy{}, ErrNotFound
	}
	if err != nil {
		return model.ReusableScanPolicy{}, err
	}
	policy.GroupIDs, err = s.postgreSQLStringColumn(
		`SELECT group_id FROM reusable_scan_policy_groups WHERE scan_policy_id=$1 ORDER BY ordinal`, id)
	return policy, err
}

func (s *PostgreSQLStore) ListReusableScanPolicies(enabledOnly bool) ([]model.ReusableScanPolicy, error) {
	query := postgresReusablePolicySelect
	if enabledOnly {
		query += ` WHERE enabled=TRUE`
	}
	rows, err := s.db.Query(query + ` ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list PostgreSQL reusable scan policies: %w", err)
	}
	policies := []model.ReusableScanPolicy{}
	for rows.Next() {
		policy, err := scanPostgreSQLReusablePolicy(rows)
		if err != nil {
			_ = rows.Close()
			return nil, err
		}
		policies = append(policies, policy)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for index := range policies {
		policies[index].GroupIDs, err = s.postgreSQLStringColumn(
			`SELECT group_id FROM reusable_scan_policy_groups WHERE scan_policy_id=$1 ORDER BY ordinal`, policies[index].ID)
		if err != nil {
			return nil, err
		}
	}
	return policies, nil
}

func scanPostgreSQLReusablePolicy(scanner interface{ Scan(...any) error }) (model.ReusableScanPolicy, error) {
	var policy model.ReusableScanPolicy
	var ports []byte
	var nextRun, lastScheduled sql.NullTime
	err := scanner.Scan(&policy.ID, &policy.Name, &policy.ScopePolicyID, &ports, &policy.Enabled, &policy.CreatedAt,
		&policy.UpdatedAt, &policy.ScheduleKind, &policy.ScheduleExpression, &policy.ScheduleTimezone,
		&policy.WindowStart, &policy.WindowEnd, &policy.RunMissed, &policy.LongRunAlertSeconds, &nextRun,
		&lastScheduled, &policy.RateLimitPerSecond, &policy.ExecutionMode, &policy.WorkerSiteID)
	if err != nil {
		return policy, err
	}
	if err := json.Unmarshal(ports, &policy.Ports); err != nil {
		return policy, fmt.Errorf("decode PostgreSQL reusable-policy ports: %w", err)
	}
	policy.NextRunAt = nullablePostgreSQLTime(nextRun)
	policy.LastScheduledAt = nullablePostgreSQLTime(lastScheduled)
	return policy, nil
}

func (s *PostgreSQLStore) UpdateReusablePolicySchedule(id string, nextRun, lastScheduled *time.Time, event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL reusable-policy schedule update: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE reusable_scan_policies SET next_run_at=$1,last_scheduled_at=$2 WHERE id=$3`,
		nextRun, lastScheduled, id); err != nil {
		return fmt.Errorf("update PostgreSQL reusable-policy schedule: %w", err)
	}
	if err := insertPostgreSQLAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgreSQLStore) ReusableScanPolicyTargets(id string) ([]model.Target, error) {
	rows, err := s.db.Query(`SELECT a.name,aa.address,spg.group_id FROM reusable_scan_policy_groups spg
		JOIN asset_group_members agm ON agm.group_id=spg.group_id JOIN assets a ON a.id=agm.asset_id
		JOIN asset_addresses aa ON aa.asset_id=a.id WHERE spg.scan_policy_id=$1 ORDER BY aa.address,spg.ordinal`, id)
	if err != nil {
		return nil, fmt.Errorf("expand PostgreSQL reusable-policy targets: %w", err)
	}
	defer rows.Close()
	byAddress := map[string]*model.Target{}
	order := []string{}
	for rows.Next() {
		var name, address, groupID string
		if err := rows.Scan(&name, &address, &groupID); err != nil {
			return nil, err
		}
		target := byAddress[address]
		if target == nil {
			target = &model.Target{Name: name, Address: address, GroupIDs: []string{}}
			byAddress[address] = target
			order = append(order, address)
		}
		target.GroupIDs = append(target.GroupIDs, groupID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Strings(order)
	targets := make([]model.Target, 0, len(order))
	for _, address := range order {
		targets = append(targets, *byAddress[address])
	}
	return targets, nil
}
