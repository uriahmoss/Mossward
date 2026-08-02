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

func (s *SQLiteStore) UpsertAssetGroup(group model.AssetGroup, event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO asset_groups(id,name,description,created_at,updated_at) VALUES(?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET name=excluded.name,description=excluded.description,updated_at=excluded.updated_at`,
		group.ID, group.Name, group.Description, formatTime(group.CreatedAt), formatTime(group.UpdatedAt))
	if err != nil {
		return fmt.Errorf("save asset group: %w", err)
	}
	if err := insertAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLiteStore) ListAssetGroups() ([]model.AssetGroup, error) {
	rows, err := s.db.Query(`SELECT id,name,description,created_at,updated_at FROM asset_groups ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list asset groups: %w", err)
	}
	groups := []model.AssetGroup{}
	for rows.Next() {
		var group model.AssetGroup
		var createdAt, updatedAt string
		if err := rows.Scan(&group.ID, &group.Name, &group.Description, &createdAt, &updatedAt); err != nil {
			_ = rows.Close()
			return nil, err
		}
		group.CreatedAt, _ = parseTime(createdAt)
		group.UpdatedAt, _ = parseTime(updatedAt)
		groups = append(groups, group)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for index := range groups {
		groups[index].AssetIDs, err = s.stringColumn(`SELECT asset_id FROM asset_group_members WHERE group_id=? ORDER BY asset_id`, groups[index].ID)
		if err != nil {
			return nil, err
		}
		groups[index].ScanPolicyIDs, err = s.stringColumn(`SELECT scan_policy_id FROM reusable_scan_policy_groups WHERE group_id=? ORDER BY scan_policy_id`, groups[index].ID)
		if err != nil {
			return nil, err
		}
	}
	return groups, nil
}

func (s *SQLiteStore) stringColumn(query, value string) ([]string, error) {
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

func (s *SQLiteStore) AssetGroupMemberships(assetID string) ([]string, error) {
	return s.stringColumn(`SELECT group_id FROM asset_group_members WHERE asset_id=? ORDER BY group_id`, assetID)
}

func (s *SQLiteStore) AddAssetGroupMember(groupID, assetID, actorID string, addedAt time.Time, event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO asset_group_members(group_id,asset_id,added_at,added_by) VALUES(?,?,?,?) ON CONFLICT(group_id,asset_id) DO NOTHING`,
		groupID, assetID, formatTime(addedAt), actorID); err != nil {
		return fmt.Errorf("add asset group member: %w", err)
	}
	if err := insertAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLiteStore) RemoveAssetGroupMember(groupID, assetID string, event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.Exec(`DELETE FROM asset_group_members WHERE group_id=? AND asset_id=?`, groupID, assetID)
	if err != nil {
		return err
	}
	changed, _ := result.RowsAffected()
	if changed != 1 {
		return ErrNotFound
	}
	if err := insertAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLiteStore) UpsertReusableScanPolicy(policy model.ReusableScanPolicy, event model.AuditEvent) error {
	ports, err := json.Marshal(policy.Ports)
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO reusable_scan_policies(id,name,scope_policy_id,ports,enabled,created_at,updated_at,schedule_kind,schedule_expression,schedule_timezone,window_start,window_end,run_missed,long_run_alert_seconds,next_run_at,last_scheduled_at,rate_limit_per_second) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET name=excluded.name,scope_policy_id=excluded.scope_policy_id,ports=excluded.ports,enabled=excluded.enabled,updated_at=excluded.updated_at,schedule_kind=excluded.schedule_kind,schedule_expression=excluded.schedule_expression,schedule_timezone=excluded.schedule_timezone,window_start=excluded.window_start,window_end=excluded.window_end,run_missed=excluded.run_missed,long_run_alert_seconds=excluded.long_run_alert_seconds,next_run_at=excluded.next_run_at,last_scheduled_at=excluded.last_scheduled_at,rate_limit_per_second=excluded.rate_limit_per_second`,
		policy.ID, policy.Name, policy.ScopePolicyID, ports, policy.Enabled, formatTime(policy.CreatedAt), formatTime(policy.UpdatedAt), policy.ScheduleKind, policy.ScheduleExpression, policy.ScheduleTimezone, policy.WindowStart, policy.WindowEnd, policy.RunMissed, policy.LongRunAlertSeconds, formatOptionalTime(policy.NextRunAt), formatOptionalTime(policy.LastScheduledAt), policy.RateLimitPerSecond)
	if err != nil {
		return fmt.Errorf("save reusable scan policy: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM reusable_scan_policy_groups WHERE scan_policy_id=?`, policy.ID); err != nil {
		return err
	}
	for index, groupID := range policy.GroupIDs {
		if _, err := tx.Exec(`INSERT INTO reusable_scan_policy_groups(scan_policy_id,group_id,ordinal) VALUES(?,?,?)`, policy.ID, groupID, index); err != nil {
			return fmt.Errorf("save scan policy group: %w", err)
		}
	}
	if err := insertAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLiteStore) ReusableScanPolicy(id string) (model.ReusableScanPolicy, error) {
	policy, err := scanReusablePolicy(s.db.QueryRow(reusablePolicySelect+` WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return model.ReusableScanPolicy{}, ErrNotFound
	}
	if err != nil {
		return model.ReusableScanPolicy{}, err
	}
	policy.GroupIDs, err = s.stringColumn(`SELECT group_id FROM reusable_scan_policy_groups WHERE scan_policy_id=? ORDER BY ordinal`, id)
	return policy, err
}

func (s *SQLiteStore) ListReusableScanPolicies(enabledOnly bool) ([]model.ReusableScanPolicy, error) {
	query := reusablePolicySelect
	if enabledOnly {
		query += ` WHERE enabled=1`
	}
	query += ` ORDER BY name`
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	items := []model.ReusableScanPolicy{}
	for rows.Next() {
		item, err := scanReusablePolicy(rows)
		if err != nil {
			_ = rows.Close()
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for index := range items {
		items[index].GroupIDs, err = s.stringColumn(`SELECT group_id FROM reusable_scan_policy_groups WHERE scan_policy_id=? ORDER BY ordinal`, items[index].ID)
		if err != nil {
			return nil, err
		}
	}
	return items, nil
}

func scanReusablePolicy(row interface{ Scan(...any) error }) (model.ReusableScanPolicy, error) {
	var policy model.ReusableScanPolicy
	var ports, createdAt, updatedAt string
	var nextRun, lastScheduled sql.NullString
	err := row.Scan(&policy.ID, &policy.Name, &policy.ScopePolicyID, &ports, &policy.Enabled, &createdAt, &updatedAt,
		&policy.ScheduleKind, &policy.ScheduleExpression, &policy.ScheduleTimezone, &policy.WindowStart, &policy.WindowEnd,
		&policy.RunMissed, &policy.LongRunAlertSeconds, &nextRun, &lastScheduled, &policy.RateLimitPerSecond)
	if err != nil {
		return policy, err
	}
	if err := json.Unmarshal([]byte(ports), &policy.Ports); err != nil {
		return policy, err
	}
	policy.CreatedAt, _ = parseTime(createdAt)
	policy.UpdatedAt, _ = parseTime(updatedAt)
	policy.NextRunAt, _ = parseOptionalTime(nextRun)
	policy.LastScheduledAt, _ = parseOptionalTime(lastScheduled)
	return policy, nil
}

const reusablePolicySelect = `SELECT id,name,scope_policy_id,ports,enabled,created_at,updated_at,schedule_kind,schedule_expression,schedule_timezone,window_start,window_end,run_missed,long_run_alert_seconds,next_run_at,last_scheduled_at,rate_limit_per_second FROM reusable_scan_policies`

func (s *SQLiteStore) UpdateReusablePolicySchedule(id string, nextRun, lastScheduled *time.Time, event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE reusable_scan_policies SET next_run_at=?,last_scheduled_at=? WHERE id=?`, formatOptionalTime(nextRun), formatOptionalTime(lastScheduled), id); err != nil {
		return err
	}
	if err := insertAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLiteStore) ReusableScanPolicyTargets(id string) ([]model.Target, error) {
	rows, err := s.db.Query(`SELECT a.name,aa.address,spg.group_id FROM reusable_scan_policy_groups spg
		JOIN asset_group_members agm ON agm.group_id=spg.group_id JOIN assets a ON a.id=agm.asset_id
		JOIN asset_addresses aa ON aa.asset_id=a.id WHERE spg.scan_policy_id=? ORDER BY aa.address,spg.ordinal`, id)
	if err != nil {
		return nil, err
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
	sort.Strings(order)
	targets := make([]model.Target, 0, len(order))
	for _, address := range order {
		targets = append(targets, *byAddress[address])
	}
	return targets, rows.Err()
}
