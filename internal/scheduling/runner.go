package scheduling

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"mossward/internal/model"
	"mossward/internal/scanner"
	"mossward/internal/store"
	"time"
)

const tickInterval = 30 * time.Second

type AlertSender interface {
	SendLongRun(model.ReusableScanPolicy, model.Scan) error
}
type PolicyLauncher interface {
	Launch(model.Scan, model.ReusableScanPolicy) error
}
type Runner struct {
	store    store.Repository
	engine   *scanner.Engine
	cancel   context.CancelFunc
	done     chan struct{}
	now      func() time.Time
	alerts   AlertSender
	launcher PolicyLauncher
}

func NewRunner(repository store.Repository, engine *scanner.Engine, alerts AlertSender, launchers ...PolicyLauncher) *Runner {
	runner := &Runner{store: repository, engine: engine, alerts: alerts, done: make(chan struct{}), now: func() time.Time { return time.Now().UTC() }}
	if len(launchers) > 0 {
		runner.launcher = launchers[0]
	}
	return runner
}
func (r *Runner) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	go r.loop(ctx)
}
func (r *Runner) Close() {
	if r.cancel == nil {
		return
	}
	r.cancel()
	<-r.done
}
func (r *Runner) loop(ctx context.Context) {
	defer close(r.done)
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()
	r.tick()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.tick()
		}
	}
}
func (r *Runner) tick() {
	policies, err := r.store.ListReusableScanPolicies(true)
	if err != nil {
		slog.Error("Could not load scheduled scan policies", "error", err)
		return
	}
	scans, err := r.store.List()
	if err != nil {
		slog.Error("Could not inspect scheduled scans", "error", err)
		return
	}
	now := r.now()
	for _, policy := range policies {
		r.process(policy, scans, now)
	}
}
func (r *Runner) process(policy model.ReusableScanPolicy, scans []model.Scan, now time.Time) {
	active := activePolicyScan(scans, policy.ID)
	inside, windowEnd, err := Window(policy, now)
	if err != nil {
		slog.Error("Scheduled policy window is invalid", "policy_id", policy.ID, "error", err)
		return
	}
	if active != nil {
		r.alertLongRun(policy, *active, now)
		if active.Status == model.StatusPaused && inside {
			active.Status = model.StatusQueued
			active.Error = ""
			active.WindowEnd = windowEnd
			if err := r.launch(*active, policy); err != nil {
				slog.Warn("Could not resume scheduled scan", "scan_id", active.ID, "error", err)
			}
		}
		if policy.NextRunAt != nil && !now.Before(*policy.NextRunAt) {
			r.advance(policy, now, "scheduled run skipped because the previous run is still active")
		}
		return
	}
	if policy.NextRunAt == nil || now.Before(*policy.NextRunAt) {
		return
	}
	if !inside {
		r.advance(policy, now, "scheduled run skipped outside its maintenance window")
		return
	}
	if !policy.RunMissed && now.Sub(*policy.NextRunAt) > 2*tickInterval {
		r.advance(policy, now, "missed scheduled run skipped by policy")
		return
	}
	scan, err := r.buildScan(policy, windowEnd, now)
	if err != nil {
		slog.Warn("Scheduled scan was not started", "policy_id", policy.ID, "error", err)
		r.advance(policy, now, "scheduled run could not start")
		return
	}
	if err := r.launch(scan, policy); err != nil {
		slog.Warn("Could not queue scheduled scan", "policy_id", policy.ID, "error", err)
		return
	}
	r.advance(policy, now, "scheduled run started")
}

func (r *Runner) launch(scan model.Scan, policy model.ReusableScanPolicy) error {
	if r.launcher != nil {
		return r.launcher.Launch(scan, policy)
	}
	if policy.ExecutionMode == model.ScanExecutionRemote {
		return errors.New("remote scanner-worker dispatch is unavailable")
	}
	return r.engine.Schedule(scan)
}

func (r *Runner) alertLongRun(policy model.ReusableScanPolicy, scan model.Scan, now time.Time) {
	if r.alerts == nil || policy.LongRunAlertSeconds <= 0 || scan.LongAlertSent {
		return
	}
	active := scan.ActiveSeconds
	if scan.Status == model.StatusRunning && scan.StartedAt != nil {
		active += int64(now.Sub(*scan.StartedAt).Seconds())
	}
	if active < policy.LongRunAlertSeconds {
		return
	}
	scan.ActiveSeconds = active
	if err := r.alerts.SendLongRun(policy, scan); err != nil {
		slog.Warn("Could not send long-running scan alert", "scan_id", scan.ID, "error", err)
		return
	}
	if err := r.store.MarkScanLongAlertSent(scan.ID); err != nil {
		slog.Error("Could not record long-running scan alert", "scan_id", scan.ID, "error", err)
	}
}
func activePolicyScan(scans []model.Scan, id string) *model.Scan {
	for index := range scans {
		scan := &scans[index]
		if scan.ScanPolicyID == id && (scan.Status == model.StatusQueued || scan.Status == model.StatusRunning || scan.Status == model.StatusPaused) {
			return scan
		}
	}
	return nil
}
func (r *Runner) buildScan(policy model.ReusableScanPolicy, windowEnd *time.Time, now time.Time) (model.Scan, error) {
	source, err := r.store.ReusableScanPolicyTargets(policy.ID)
	if err != nil || len(source) == 0 {
		return model.Scan{}, errors.New("policy has no target addresses")
	}
	scope, err := r.store.ScopePolicy(policy.ScopePolicyID)
	if err != nil || !scope.Enabled {
		return model.Scan{}, errors.New("authorization scope unavailable")
	}
	raw := make([]string, 0, len(source))
	provenance := map[string]model.Target{}
	for _, target := range source {
		raw = append(raw, target.Address)
		provenance[target.Address] = target
	}
	targets, ports, err := r.engine.ValidateWithPolicy(model.CreateScanRequest{Targets: raw, Ports: policy.Ports}, scope)
	if err != nil {
		return model.Scan{}, err
	}
	for index := range targets {
		if item, ok := provenance[targets[index].Address]; ok {
			targets[index] = item
		}
	}
	id, err := scheduleID()
	if err != nil {
		return model.Scan{}, err
	}
	return model.Scan{ID: id, Name: policy.Name, Targets: targets, Ports: ports, Status: model.StatusQueued, Observations: []model.ServiceObservation{}, Findings: []model.Finding{}, CVEMatches: []model.CVEMatch{}, TotalChecks: len(targets) * len(ports), CreatedAt: now, ScopePolicyID: scope.ID, MaxConcurrent: scope.MaxConcurrent, ScanPolicyID: policy.ID, WindowEnd: windowEnd, RateLimitPerSecond: policy.RateLimitPerSecond}, nil
}
func (r *Runner) advance(policy model.ReusableScanPolicy, now time.Time, reason string) {
	last := now
	var next *time.Time
	if policy.ScheduleKind != "once" {
		location, err := time.LoadLocation(policy.ScheduleTimezone)
		if err == nil {
			value, nextErr := Next(policy, now, location)
			if nextErr == nil {
				next = &value
			}
		}
	}
	event := model.AuditEvent{OccurredAt: now, Action: "scanner.schedule.evaluated", Severity: model.AuditInfo, TargetType: "scan_policy", TargetID: policy.ID, Details: `{"result":"` + reason + `"}`}
	if err := r.store.UpdateReusablePolicySchedule(policy.ID, next, &last, event); err != nil {
		slog.Error("Could not advance scan schedule", "policy_id", policy.ID, "error", err)
	}
}
func scheduleID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}
