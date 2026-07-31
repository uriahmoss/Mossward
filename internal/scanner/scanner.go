package scanner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"mossward/internal/config"
	"mossward/internal/model"
	"mossward/internal/store"
)

var ErrQueueFull = errors.New("scan queue is full")

type Engine struct {
	cfg    config.Config
	store  *store.FileStore
	nets   []*net.IPNet
	queue  chan model.Scan
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	state  sync.Mutex
	closed bool
}

func New(cfg config.Config, repository *store.FileStore) (*Engine, error) {
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
	if err := repository.ReconcileInterrupted(); err != nil {
		return nil, fmt.Errorf("reconcile interrupted scans: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	engine := &Engine{
		cfg: cfg, store: repository, nets: networks,
		queue: make(chan model.Scan, cfg.QueueSize), ctx: ctx, cancel: cancel,
	}
	engine.wg.Add(1)
	go engine.schedule()
	return engine, nil
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
	started := time.Now().UTC()
	scan.Status = model.StatusRunning
	scan.StartedAt = &started
	if err := e.store.Save(scan); err != nil {
		e.fail(scan, err.Error())
		return
	}

	type job struct {
		target model.Target
		port   int
	}
	jobs := make(chan job)
	results := make(chan model.Finding)
	var workers sync.WaitGroup

	for i := 0; i < e.cfg.MaxConcurrent; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for {
				select {
				case <-e.ctx.Done():
					return
				case item, ok := <-jobs:
					if !ok {
						return
					}
					if finding, ok := e.probe(e.ctx, item.target, item.port); ok {
						select {
						case results <- finding:
						case <-e.ctx.Done():
							return
						}
					}
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, target := range scan.Targets {
			for _, port := range scan.Ports {
				select {
				case jobs <- job{target: target, port: port}:
				case <-e.ctx.Done():
					return
				}
			}
		}
	}()
	go func() {
		workers.Wait()
		close(results)
	}()

	for finding := range results {
		scan.Findings = append(scan.Findings, finding)
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
	}
}

func (e *Engine) fail(scan model.Scan, message string) {
	completed := time.Now().UTC()
	scan.Status = model.StatusFailed
	scan.Error = message
	scan.CompletedAt = &completed
	_ = e.store.Save(scan)
}

func (e *Engine) probe(parent context.Context, target model.Target, port int) (model.Finding, bool) {
	ctx, cancel := context.WithTimeout(parent, e.cfg.ConnectTimeout)
	defer cancel()
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(target.Address, fmt.Sprint(port)))
	if err != nil {
		return model.Finding{}, false
	}
	_ = conn.Close()
	service := serviceName(port)
	return model.Finding{
		ID:          id(),
		Target:      target.Name,
		Address:     target.Address,
		Port:        port,
		Service:     service,
		Severity:    "info",
		Title:       fmt.Sprintf("TCP service reachable on port %d", port),
		Evidence:    "A TCP connection completed successfully to the approved IP address. No payload or exploit was sent.",
		Remediation: "Confirm the service is required and restricted to intended network sources.",
		ObservedAt:  time.Now().UTC(),
	}, true
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

func serviceName(port int) string {
	services := map[int]string{22: "ssh", 80: "http", 443: "https", 445: "smb", 3389: "rdp", 5432: "postgresql", 6379: "redis", 8080: "http-alt", 8443: "https-alt"}
	if name, ok := services[port]; ok {
		return name
	}
	return "unknown"
}

func id() string {
	value := make([]byte, 12)
	_, _ = rand.Read(value)
	return hex.EncodeToString(value)
}
