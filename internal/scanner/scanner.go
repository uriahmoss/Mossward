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

const progressSaveDivisor = 100

type Engine struct {
	cfg    config.Config
	store  store.Repository
	nets   []*net.IPNet
	probes *probe.Inspector
	queue  chan model.Scan
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	state  sync.Mutex
	closed bool
}

type scanJob struct {
	target model.Target
	port   int
}

type probeResult struct {
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
		e.fail(scan, ErrQueueFull.Error())
		return ErrQueueFull
	}
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
			e.fail(scan, "scan canceled during process shutdown")
		default:
			return
		}
	}
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
	slog.Info("Scan started", "scan_id", scan.ID, "checks", len(scan.Targets)*len(scan.Ports))
	started := time.Now().UTC()
	scan.Status = model.StatusRunning
	scan.StartedAt = &started
	scan.TotalChecks = len(scan.Targets) * len(scan.Ports)
	scan.DoneChecks = 0
	if err := e.store.Save(scan); err != nil {
		e.fail(scan, err.Error())
		return
	}

	jobs := make(chan scanJob)
	results := make(chan probeResult)
	e.startWorkers(scan, jobs, results)
	go e.queueJobs(scan, jobs)

	saveInterval := max(1, scan.TotalChecks/progressSaveDivisor)
	for result := range results {
		scan.DoneChecks++
		if result.observation != nil {
			scan.Observations = append(scan.Observations, *result.observation)
			scan.Findings = append(scan.Findings, result.findings...)
			e.addCVEMatches(&scan, *result.observation)
		}
		if scan.DoneChecks%saveInterval == 0 {
			e.saveProgress(scan)
		}
	}
	if e.ctx.Err() != nil {
		e.fail(scan, "scan canceled during process shutdown")
		return
	}
	completed := time.Now().UTC()
	scan.Status = model.StatusCompleted
	scan.CompletedAt = &completed
	if err := e.store.Save(scan); err != nil {
		e.fail(scan, err.Error())
		return
	}
	slog.Info("Scan completed", "scan_id", scan.ID, "observations", len(scan.Observations), "findings", len(scan.Findings), "cve_matches", len(scan.CVEMatches))
}

func (e *Engine) startWorkers(scan model.Scan, jobs <-chan scanJob, results chan<- probeResult) {
	var workers sync.WaitGroup
	workerCount := scan.MaxConcurrent
	if workerCount < 1 || workerCount > e.cfg.MaxConcurrent {
		workerCount = e.cfg.MaxConcurrent
	}
	for range workerCount {
		workers.Add(1)
		go func() {
			defer workers.Done()
			e.processJobs(jobs, results)
		}()
	}
	go func() {
		workers.Wait()
		close(results)
	}()
}

func (e *Engine) processJobs(jobs <-chan scanJob, results chan<- probeResult) {
	for {
		select {
		case <-e.ctx.Done():
			return
		case item, ok := <-jobs:
			if !ok {
				return
			}
			result := e.inspect(item)
			select {
			case results <- result:
			case <-e.ctx.Done():
				return
			}
		}
	}
}

func (e *Engine) inspect(item scanJob) probeResult {
	observation, findings, reachable := e.probes.Inspect(e.ctx, item.target, item.port)
	if !reachable {
		return probeResult{}
	}
	return probeResult{observation: &observation, findings: findings}
}

func (e *Engine) queueJobs(scan model.Scan, jobs chan<- scanJob) {
	defer close(jobs)
	for _, target := range scan.Targets {
		for _, port := range scan.Ports {
			select {
			case jobs <- scanJob{target: target, port: port}:
			case <-e.ctx.Done():
				return
			}
		}
	}
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
