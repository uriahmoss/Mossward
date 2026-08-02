package scanner

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"mossward/internal/config"
	"mossward/internal/model"
	"mossward/internal/probe"
	"mossward/internal/store"
)

var ErrQueueFull = errors.New("scan queue is full")
var ErrScanNotCancelable = errors.New("scan is not in a cancelable state")

const progressSaveDivisor = 100

type Engine struct {
	cfg      config.Config
	store    store.Repository
	nets     []*net.IPNet
	probes   *probe.Inspector
	queue    chan model.Scan
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	state    sync.Mutex
	closed   bool
	active   map[string]context.CancelFunc
	canceled map[string]bool
}

type scanJob struct {
	target model.Target
	port   int
}

type probeResult struct {
	job         scanJob
	observation *model.ServiceObservation
	findings    []model.Finding
}

func New(cfg config.Config, repository store.Repository) (*Engine, error) {
	if cfg.MaxConcurrent < 1 {
		return nil, errors.New("MaxConcurrent must be at least 1")
	}
	if cfg.QueueSize < 1 {
		return nil, errors.New("QueueSize must be at least 1")
	}
	if cfg.ConnectTimeout <= 0 {
		return nil, errors.New("ConnectTimeout must be positive")
	}
	var networks []*net.IPNet
	for _, raw := range cfg.AllowedCIDRs {
		_, network, err := net.ParseCIDR(strings.TrimSpace(raw))
		if err != nil {
			return nil, fmt.Errorf("invalid allowed CIDR %q: %w", raw, err)
		}
		networks = append(networks, network)
	}
	if len(networks) == 0 {
		return nil, errors.New("at least one allowed CIDR is required")
	}
	ports := make([]int, 0, len(cfg.AllowedPorts))
	for port := range cfg.AllowedPorts {
		ports = append(ports, port)
	}
	sort.Ints(ports)
	now := time.Now().UTC()
	defaultPolicy := model.ScopePolicy{ID: "default", Name: "Default environment policy", AllowedCIDRs: cfg.AllowedCIDRs,
		AllowedPorts: ports, MaxTargets: cfg.MaxTargets, MaxConcurrent: cfg.MaxConcurrent, Enabled: true,
		CreatedAt: now, UpdatedAt: now}
	if err := repository.EnsureDefaultScopePolicy(defaultPolicy); err != nil {
		return nil, fmt.Errorf("ensure default scope policy: %w", err)
	}
	if err := repository.ReconcileInterrupted(); err != nil {
		return nil, fmt.Errorf("reconcile interrupted scans: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	engine := &Engine{
		cfg: cfg, store: repository, nets: networks, probes: probe.New(cfg.ConnectTimeout),
		queue: make(chan model.Scan, cfg.QueueSize), ctx: ctx, cancel: cancel,
		active: map[string]context.CancelFunc{}, canceled: map[string]bool{},
	}
	engine.wg.Add(1)
	go engine.schedule()
	return engine, nil
}

func (e *Engine) ValidateWithPolicy(req model.CreateScanRequest, policy model.ScopePolicy) ([]model.Target, []int, error) {
	validator, err := e.policyValidator(policy)
	if err != nil {
		return nil, nil, err
	}
	return validator.Validate(req)
}

func (e *Engine) ValidatePolicy(policy model.ScopePolicy) error {
	_, err := e.policyValidator(policy)
	return err
}

func (e *Engine) policyValidator(policy model.ScopePolicy) (*Engine, error) {
	if !policy.Enabled {
		return nil, errors.New("scope policy is disabled")
	}
	if policy.MaxTargets < 1 || policy.MaxTargets > e.cfg.MaxTargets {
		return nil, fmt.Errorf("scope-policy target limit must be between 1 and %d", e.cfg.MaxTargets)
	}
	if policy.MaxConcurrent < 1 || policy.MaxConcurrent > e.cfg.MaxConcurrent {
		return nil, fmt.Errorf("scope-policy concurrency must be between 1 and %d", e.cfg.MaxConcurrent)
	}
	networks := make([]*net.IPNet, 0, len(policy.AllowedCIDRs))
	for _, raw := range policy.AllowedCIDRs {
		_, network, err := net.ParseCIDR(strings.TrimSpace(raw))
		if err != nil {
			return nil, fmt.Errorf("invalid scope-policy CIDR %q: %w", raw, err)
		}
		networks = append(networks, network)
	}
	if len(networks) == 0 {
		return nil, errors.New("scope policy requires at least one authorized CIDR")
	}
	allowedPorts := make(map[int]bool, len(policy.AllowedPorts))
	for _, port := range policy.AllowedPorts {
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid scope-policy port %d", port)
		}
		allowedPorts[port] = true
	}
	if len(allowedPorts) == 0 {
		return nil, errors.New("scope policy requires at least one allowed port")
	}
	validatorConfig := e.cfg
	validatorConfig.MaxTargets = policy.MaxTargets
	validatorConfig.AllowedPorts = allowedPorts
	return &Engine{cfg: validatorConfig, nets: networks}, nil
}

func (e *Engine) Validate(req model.CreateScanRequest) ([]model.Target, []int, error) {
	if len(req.Targets) == 0 || len(req.Targets) > e.cfg.MaxTargets {
		return nil, nil, fmt.Errorf("provide between 1 and %d targets", e.cfg.MaxTargets)
	}
	ports := append([]int(nil), req.Ports...)
	if len(ports) == 0 {
		for port := range e.cfg.AllowedPorts {
			ports = append(ports, port)
		}
	}
	sort.Ints(ports)
	ports = deduplicatePorts(ports)
	for _, port := range ports {
		if !e.cfg.AllowedPorts[port] {
			return nil, nil, fmt.Errorf("port %d is not in the configured allowlist", port)
		}
	}

	var targets []model.Target
	seen := make(map[string]bool)
	for _, requested := range req.Targets {
		name := strings.TrimSpace(requested)
		if name == "" {
			return nil, nil, errors.New("targets cannot be blank")
		}
		if strings.Contains(name, "/") {
			prefix, err := netip.ParsePrefix(name)
			if err != nil {
				return nil, nil, fmt.Errorf("invalid CIDR target %q: %w", name, err)
			}
			if err := e.addPrefixTargets(name, prefix, &targets, seen); err != nil {
				return nil, nil, err
			}
			continue
		}
		if start, end, ok := parseAddressRange(name); ok {
			if err := e.addRangeTargets(name, start, end, &targets, seen); err != nil {
				return nil, nil, err
			}
			continue
		}
		ips, err := net.LookupIP(name)
		if err != nil || len(ips) == 0 {
			return nil, nil, fmt.Errorf("cannot resolve target %q", name)
		}
		for _, ip := range ips {
			address, ok := netip.AddrFromSlice(ip)
			if !ok {
				return nil, nil, fmt.Errorf("target %q resolved to an invalid address", name)
			}
			if err := e.addTarget(name, address.Unmap(), &targets, seen); err != nil {
				return nil, nil, err
			}
		}
	}
	return targets, ports, nil
}

func (e *Engine) addPrefixTargets(name string, prefix netip.Prefix, targets *[]model.Target, seen map[string]bool) error {
	prefix = prefix.Masked()
	address := prefix.Addr()
	skipEdges := address.Is4() && prefix.Bits() <= 30
	for prefix.Contains(address) {
		if !skipEdges || (address != prefix.Addr() && prefix.Contains(address.Next())) {
			if err := e.addTarget(name, address, targets, seen); err != nil {
				return err
			}
		}
		address = address.Next()
		if !address.IsValid() {
			break
		}
	}
	if len(*targets) == 0 {
		return fmt.Errorf("CIDR target %q contains no scannable host addresses", name)
	}
	return nil
}

func (e *Engine) addRangeTargets(name string, start, end netip.Addr, targets *[]model.Target, seen map[string]bool) error {
	start = start.Unmap()
	end = end.Unmap()
	if start.BitLen() != end.BitLen() || start.Compare(end) > 0 {
		return fmt.Errorf("invalid IP range %q: start must be before end and use the same address family", name)
	}
	for address := start; ; address = address.Next() {
		if err := e.addTarget(name, address, targets, seen); err != nil {
			return err
		}
		if address == end {
			break
		}
	}
	return nil
}

func (e *Engine) addTarget(name string, address netip.Addr, targets *[]model.Target, seen map[string]bool) error {
	if !e.allowed(net.IP(address.AsSlice())) {
		return fmt.Errorf("target %q includes address %s outside the configured network allowlist", name, address)
	}
	key := address.String()
	if seen[key] {
		return nil
	}
	if len(*targets) >= e.cfg.MaxTargets {
		return fmt.Errorf("expanded target addresses exceed the limit of %d", e.cfg.MaxTargets)
	}
	*targets = append(*targets, model.Target{Name: name, Address: key})
	seen[key] = true
	return nil
}

func parseAddressRange(value string) (netip.Addr, netip.Addr, bool) {
	startRaw, endRaw, ok := strings.Cut(value, "-")
	if !ok {
		return netip.Addr{}, netip.Addr{}, false
	}
	start, startErr := netip.ParseAddr(strings.TrimSpace(startRaw))
	end, endErr := netip.ParseAddr(strings.TrimSpace(endRaw))
	if startErr != nil || endErr != nil {
		return netip.Addr{}, netip.Addr{}, false
	}
	return start, end, true
}

func (e *Engine) Schedule(scan model.Scan) error {
	e.state.Lock()
	defer e.state.Unlock()
	if e.closed {
		return errors.New("scanner is shutting down")
	}
	if err := e.store.Save(scan); err != nil {
		return err
	}
	select {
	case e.queue <- scan:
		slog.Info("Scan queued", "scan_id", scan.ID, "targets", len(scan.Targets), "ports", len(scan.Ports))
		return nil
	default:
		e.interrupt(scan, ErrQueueFull.Error())
		return ErrQueueFull
	}
}

func (e *Engine) Cancel(id string) error {
	scan, err := e.store.Get(id)
	if err != nil {
		return err
	}
	if !cancelableScanStatus(scan.Status) {
		return ErrScanNotCancelable
	}
	e.state.Lock()
	cancel := e.active[id]
	if cancel != nil || scan.Status == model.StatusQueued || scan.Status == model.StatusRunning {
		e.canceled[id] = true
	}
	e.state.Unlock()
	if cancel != nil {
		cancel()
	}
	e.finishCanceled(scan)
	return nil
}

func cancelableScanStatus(status model.ScanStatus) bool {
	return status == model.StatusQueued || status == model.StatusRunning || status == model.StatusPaused
}

func (e *Engine) Shutdown() {
	e.state.Lock()
	if e.closed {
		e.state.Unlock()
		return
	}
	e.closed = true
	e.state.Unlock()
	e.cancel()
	e.wg.Wait()
	for {
		select {
		case scan := <-e.queue:
			if e.consumeCanceled(scan.ID) {
				e.finishCanceled(scan)
				continue
			}
			e.interrupt(scan, "scan canceled during process shutdown")
		default:
			return
		}
	}
}

func (e *Engine) consumeCanceled(id string) bool {
	e.state.Lock()
	defer e.state.Unlock()
	if !e.canceled[id] {
		return false
	}
	delete(e.canceled, id)
	return true
}

func (e *Engine) Ready() bool {
	e.state.Lock()
	defer e.state.Unlock()
	return !e.closed
}

func (e *Engine) schedule() {
	defer e.wg.Done()
	for {
		select {
		case <-e.ctx.Done():
			return
		case scan := <-e.queue:
			e.run(scan)
		}
	}
}

func (e *Engine) run(scan model.Scan) {
	ctx, cancel, ok := e.beginScan(scan.ID)
	if !ok {
		e.finishCanceled(scan)
		return
	}
	defer e.endScan(scan.ID, cancel)
	slog.Info("Scan started", "scan_id", scan.ID, "checks", len(scan.Targets)*len(scan.Ports), "rate_limit_per_second", scan.RateLimitPerSecond)
	started := time.Now().UTC()
	scan.Status = model.StatusRunning
	scan.StartedAt = &started
	scan.TotalChecks = len(scan.Targets) * len(scan.Ports)
	scan.DoneChecks = len(scan.Checkpoints)
	if err := e.store.Save(scan); err != nil {
		e.fail(scan, err.Error())
		return
	}

	jobs := make(chan scanJob)
	results := make(chan probeResult)
	queueClosed := make(chan bool, 1)
	e.startWorkers(ctx, scan, jobs, results)
	go func() { queueClosed <- e.queueJobs(ctx, scan, jobs) }()

	saveInterval := max(1, scan.TotalChecks/progressSaveDivisor)
	for result := range results {
		scan.DoneChecks++
		scan.Checkpoints = append(scan.Checkpoints, model.ScanCheckpoint{Address: result.job.target.Address, Port: result.job.port, CompletedAt: time.Now().UTC()})
		if result.observation != nil {
			scan.Observations = append(scan.Observations, *result.observation)
			scan.Findings = append(scan.Findings, result.findings...)
			e.addCVEMatches(&scan, *result.observation)
		}
		if scan.DoneChecks%saveInterval == 0 {
			e.saveProgress(scan)
		}
	}
	closedByWindow := <-queueClosed
	if e.ctx.Err() != nil {
		e.interrupt(scan, "scan canceled during process shutdown")
		return
	}
	if ctx.Err() != nil {
		e.finishCanceled(scan)
		return
	}
	completed := time.Now().UTC()
	scan.ActiveSeconds += max(0, int64(completed.Sub(started).Seconds()))
	if closedByWindow && scan.DoneChecks < scan.TotalChecks {
		scan.Status = model.StatusPaused
		scan.Error = "scan paused at the end of its maintenance window"
		scan.StartedAt = nil
		if err := e.store.Save(scan); err != nil {
			e.fail(scan, err.Error())
			return
		}
		slog.Info("Scheduled scan paused", "scan_id", scan.ID, "completed_checks", scan.DoneChecks)
		return
	}
	scan.Status = model.StatusCompleted
	scan.CompletedAt = &completed
	if err := e.store.Save(scan); err != nil {
		e.fail(scan, err.Error())
		return
	}
	slog.Info("Scan completed", "scan_id", scan.ID, "observations", len(scan.Observations), "findings", len(scan.Findings), "cve_matches", len(scan.CVEMatches))
}

func (e *Engine) beginScan(id string) (context.Context, context.CancelFunc, bool) {
	ctx, cancel := context.WithCancel(e.ctx)
	e.state.Lock()
	defer e.state.Unlock()
	if e.canceled[id] {
		delete(e.canceled, id)
		cancel()
		return ctx, cancel, false
	}
	e.active[id] = cancel
	return ctx, cancel, true
}

func (e *Engine) endScan(id string, cancel context.CancelFunc) {
	cancel()
	e.state.Lock()
	delete(e.active, id)
	delete(e.canceled, id)
	e.state.Unlock()
}

func (e *Engine) startWorkers(ctx context.Context, scan model.Scan, jobs <-chan scanJob, results chan<- probeResult) {
	var workers sync.WaitGroup
	workerCount := scan.MaxConcurrent
	if workerCount < 1 || workerCount > e.cfg.MaxConcurrent {
		workerCount = e.cfg.MaxConcurrent
	}
	for range workerCount {
		workers.Add(1)
		go func() {
			defer workers.Done()
			e.processJobs(ctx, jobs, results)
		}()
	}
	go func() {
		workers.Wait()
		close(results)
	}()
}

func (e *Engine) processJobs(ctx context.Context, jobs <-chan scanJob, results chan<- probeResult) {
	for {
		select {
		case <-ctx.Done():
			return
		case item, ok := <-jobs:
			if !ok {
				return
			}
			result := e.inspect(ctx, item)
			select {
			case results <- result:
			case <-ctx.Done():
				return
			}
		}
	}
}

func (e *Engine) inspect(ctx context.Context, item scanJob) probeResult {
	observation, findings, reachable := e.probes.Inspect(ctx, item.target, item.port)
	if !reachable {
		return probeResult{job: item}
	}
	return probeResult{job: item, observation: &observation, findings: findings}
}

func (e *Engine) queueJobs(ctx context.Context, scan model.Scan, jobs chan<- scanJob) bool {
	defer close(jobs)
	pace, stopPace := scanPace(scan.RateLimitPerSecond)
	defer stopPace()
	completed := map[string]bool{}
	for _, item := range scan.Checkpoints {
		completed[fmt.Sprintf("%s:%d", item.Address, item.Port)] = true
	}
	var window <-chan time.Time
	if scan.WindowEnd != nil {
		duration := time.Until(*scan.WindowEnd)
		if duration <= 0 {
			return true
		}
		timer := time.NewTimer(duration)
		defer timer.Stop()
		window = timer.C
	}
	for _, target := range scan.Targets {
		for _, port := range scan.Ports {
			if completed[fmt.Sprintf("%s:%d", target.Address, port)] {
				continue
			}
			if waitForDispatch(ctx, pace, window) {
				return window != nil && ctx.Err() == nil
			}
			select {
			case jobs <- scanJob{target: target, port: port}:
			case <-ctx.Done():
				return false
			case <-window:
				return true
			}
		}
	}
	return false
}

func scanPace(checksPerSecond int) (<-chan time.Time, func()) {
	if checksPerSecond <= 0 {
		return nil, func() {}
	}
	ticker := time.NewTicker(time.Second / time.Duration(checksPerSecond))
	return ticker.C, ticker.Stop
}

func waitForDispatch(ctx context.Context, pace, window <-chan time.Time) bool {
	if pace == nil {
		return false
	}
	select {
	case <-pace:
		return false
	case <-ctx.Done():
		return true
	case <-window:
		return true
	}
}

func (e *Engine) finishCanceled(scan model.Scan) {
	now := time.Now().UTC()
	if scan.StartedAt != nil {
		scan.ActiveSeconds += max(0, int64(now.Sub(*scan.StartedAt).Seconds()))
	}
	scan.Status = model.StatusCanceled
	scan.Error = "scan canceled by user"
	scan.CompletedAt = &now
	if err := e.store.Save(scan); err != nil {
		slog.Error("Could not persist canceled scan state", "scan_id", scan.ID, "error", err)
		return
	}
	slog.Info("Scan canceled", "scan_id", scan.ID, "completed_checks", scan.DoneChecks)
}

func (e *Engine) addCVEMatches(scan *model.Scan, observation model.ServiceObservation) {
	matches, err := e.store.MatchObservation(observation)
	if err != nil {
		slog.Warn("CVE correlation skipped for an observation", "scan_id", scan.ID, "observation_id", observation.ID, "error", err)
		return
	}
	scan.CVEMatches = append(scan.CVEMatches, matches...)
}

func (e *Engine) saveProgress(scan model.Scan) {
	if err := e.store.Save(scan); err != nil {
		slog.Warn("Could not persist intermediate scan progress", "scan_id", scan.ID, "completed_checks", scan.DoneChecks, "error", err)
	}
}

func (e *Engine) fail(scan model.Scan, message string) {
	slog.Error("Scan failed", "scan_id", scan.ID, "error", message)
	completed := time.Now().UTC()
	scan.Status = model.StatusFailed
	scan.Error = message
	scan.CompletedAt = &completed
	if err := e.store.Save(scan); err != nil {
		slog.Error("Could not persist failed scan state", "scan_id", scan.ID, "error", err)
	}
}

func (e *Engine) interrupt(scan model.Scan, message string) {
	if scan.ScanPolicyID == "" {
		e.fail(scan, message)
		return
	}
	now := time.Now().UTC()
	if scan.StartedAt != nil {
		scan.ActiveSeconds += max(0, int64(now.Sub(*scan.StartedAt).Seconds()))
	}
	scan.Status = model.StatusPaused
	scan.Error = message
	scan.StartedAt = nil
	scan.CompletedAt = nil
	if err := e.store.Save(scan); err != nil {
		slog.Error("Could not persist paused scheduled scan", "scan_id", scan.ID, "error", err)
		return
	}
	slog.Info("Scheduled scan paused", "scan_id", scan.ID, "reason", message)
}

func (e *Engine) allowed(ip net.IP) bool {
	for _, network := range e.nets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func deduplicatePorts(ports []int) []int {
	result := ports[:0]
	for _, port := range ports {
		if len(result) == 0 || result[len(result)-1] != port {
			result = append(result, port)
		}
	}
	return result
}
