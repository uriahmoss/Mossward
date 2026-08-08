package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"

	"mossward/internal/agentidentity"
	"mossward/internal/agentupdatecatalog"
	identity "mossward/internal/auth"
	"mossward/internal/config"
	"mossward/internal/model"
	"mossward/internal/notification"
	"mossward/internal/scanner"
	"mossward/internal/store"
	"mossward/internal/transport"
	"mossward/web"
)

type API struct {
	cfg               config.Config
	store             store.Repository
	scanner           *scanner.Engine
	auth              *identity.Service
	certificateStatus func() transport.ACMEStatus
	agentIdentity     *agentidentity.Service
	agentUpdates      *agentupdatecatalog.Service
	notifications     *notification.Service
	policyLauncher    PolicyLauncher
}

type PolicyLauncher interface {
	Launch(model.Scan, model.ReusableScanPolicy) error
}

const (
	maxRequestBodyBytes = 64 << 10
	maxScanNameLength   = 100
	defaultNewsLimit    = 6
)

type RuntimeOptions struct {
	CertificateStatus func() transport.ACMEStatus
	AgentIdentity     *agentidentity.Service
	AgentUpdates      *agentupdatecatalog.Service
	Notifications     *notification.Service
	PolicyLauncher    PolicyLauncher
}

func New(cfg config.Config, repository store.Repository, engine *scanner.Engine, identityService *identity.Service,
	options ...RuntimeOptions) http.Handler {
	api := &API{cfg: cfg, store: repository, scanner: engine, auth: identityService}
	if len(options) > 0 {
		api.certificateStatus = options[0].CertificateStatus
		api.agentIdentity = options[0].AgentIdentity
		api.agentUpdates = options[0].AgentUpdates
		api.notifications = options[0].Notifications
		api.policyLauncher = options[0].PolicyLauncher
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", api.health)
	mux.HandleFunc("GET /api/ready", api.readiness)
	mux.HandleFunc("GET /api/admin/certificate-status", api.getCertificateStatus)
	api.registerAgentIdentityRoutes(mux)
	api.registerAgentUpdateRoutes(mux)
	api.registerAssetGroupRoutes(mux)
	api.registerNotificationRoutes(mux)
	mux.HandleFunc("GET /api/config", api.getConfig)
	mux.HandleFunc("GET /api/scans", api.listScans)
	mux.HandleFunc("POST /api/scans", api.createScan)
	mux.HandleFunc("GET /api/scans/{id}", api.getScan)
	mux.HandleFunc("POST /api/scans/{id}/cancel", api.cancelScan)
	mux.HandleFunc("PATCH /api/findings/{id}/workflow", api.updateFindingWorkflow)
	api.registerReportingRoutes(mux)
	mux.HandleFunc("GET /api/assets", api.listAssets)
	mux.HandleFunc("GET /api/assets/{id}", api.getAsset)
	mux.HandleFunc("PATCH /api/assets/{id}", api.updateAsset)
	mux.HandleFunc("PATCH /api/assets/{id}/lifecycle", api.updateAssetLifecycle)
	mux.HandleFunc("GET /api/admin/asset-aging", api.getAssetAgingSettings)
	mux.HandleFunc("PATCH /api/admin/asset-aging", api.updateAssetAgingSettings)
	mux.HandleFunc("POST /api/admin/assets/merge", api.mergeAssets)
	mux.HandleFunc("GET /api/intelligence/news", api.intelligenceNews)
	mux.HandleFunc("GET /api/intelligence/status", api.intelligenceStatus)
	api.registerIdentityRoutes(mux)
	mux.Handle("/", http.FileServer(http.FS(web.Files)))
	return api.trustedProxyRequest(api.transportSecurity(securityHeaders(api.identityGate(mux))))
}

func (a *API) getCertificateStatus(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdministrator(w, r); !ok {
		return
	}
	if a.certificateStatus == nil {
		writeJSON(w, http.StatusOK, map[string]string{"mode": string(a.cfg.TransportMode), "state": "not_managed"})
		return
	}
	writeJSON(w, http.StatusOK, a.certificateStatus())
}

func (a *API) trustedProxyRequest(next http.Handler) http.Handler {
	prefixes := make([]netip.Prefix, 0, len(a.cfg.TrustedProxyCIDRs))
	for _, raw := range a.cfg.TrustedProxyCIDRs {
		if prefix, err := netip.ParsePrefix(raw); err == nil {
			prefixes = append(prefixes, prefix)
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peer, ok := remoteAddress(r.RemoteAddr)
		if !ok || !addressInPrefixes(peer, prefixes) {
			next.ServeHTTP(w, r)
			return
		}
		request := r.Clone(r.Context())
		if client, found := forwardedClient(r.Header.Values("X-Forwarded-For"), prefixes); found {
			request.RemoteAddr = netip.AddrPortFrom(client, 0).String()
		}
		if forwardedScheme := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); forwardedScheme == "https" {
			request.URL.Scheme = forwardedScheme
		}
		next.ServeHTTP(w, request)
	})
}

func (a *API) transportSecurity(next http.Handler) http.Handler {
	publicHost := ""
	if origin, err := url.Parse(a.cfg.PublicOrigin); err == nil {
		publicHost = origin.Host
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.cfg.TransportMode == config.TransportProxy && r.URL.Scheme != "https" {
			writeError(w, http.StatusBadRequest, "HTTPS proxy connection required")
			return
		}
		hosted := a.cfg.TransportMode == config.TransportTLS || a.cfg.TransportMode == config.TransportACME || a.cfg.TransportMode == config.TransportProxy
		if hosted && !strings.EqualFold(r.Host, publicHost) {
			writeError(w, http.StatusMisdirectedRequest, "unexpected request host")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func remoteAddress(value string) (netip.Addr, bool) {
	if addressPort, err := netip.ParseAddrPort(value); err == nil {
		return addressPort.Addr().Unmap(), true
	}
	address, err := netip.ParseAddr(value)
	return address.Unmap(), err == nil
}

func forwardedClient(headers []string, trusted []netip.Prefix) (netip.Addr, bool) {
	values := []string{}
	for _, header := range headers {
		values = append(values, strings.Split(header, ",")...)
	}
	for index := len(values) - 1; index >= 0; index-- {
		address, err := netip.ParseAddr(strings.TrimSpace(values[index]))
		if err != nil {
			return netip.Addr{}, false
		}
		address = address.Unmap()
		if !addressInPrefixes(address, trusted) {
			return address, true
		}
	}
	return netip.Addr{}, false
}

func addressInPrefixes(address netip.Addr, prefixes []netip.Prefix) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func (a *API) intelligenceNews(w http.ResponseWriter, _ *http.Request) {
	items, err := a.store.ListCriticalNews(defaultNewsLimit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load CVE intelligence")
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (a *API) intelligenceStatus(w http.ResponseWriter, _ *http.Request) {
	status, err := a.store.FeedStatus()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load feed status")
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (a *API) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *API) readiness(w http.ResponseWriter, _ *http.Request) {
	if !a.scanner.Ready() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
		return
	}
	initialized, err := a.auth.Initialized()
	if err != nil {
		slog.Error("Readiness check could not query identity state", "error", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
		return
	}
	if !initialized {
		status := http.StatusOK
		if a.cfg.TransportMode == config.TransportTLS || a.cfg.TransportMode == config.TransportACME || a.cfg.TransportMode == config.TransportProxy {
			status = http.StatusServiceUnavailable
		}
		writeJSON(w, status, map[string]string{"status": "setup_required"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (a *API) getConfig(w http.ResponseWriter, _ *http.Request) {
	var ports []int
	for port := range a.cfg.AllowedPorts {
		ports = append(ports, port)
	}
	sort.Ints(ports)
	writeJSON(w, http.StatusOK, map[string]any{
		"allowed_cidrs": a.cfg.AllowedCIDRs,
		"allowed_ports": ports,
		"max_targets":   a.cfg.MaxTargets,
	})
}

func (a *API) listScans(w http.ResponseWriter, _ *http.Request) {
	scans, err := a.store.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load scans")
		return
	}
	writeJSON(w, http.StatusOK, scans)
}

func (a *API) getScan(w http.ResponseWriter, r *http.Request) {
	scan, err := a.store.Get(r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "scan not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load scan")
		return
	}
	writeJSON(w, http.StatusOK, scan)
}

func (a *API) cancelScan(w http.ResponseWriter, r *http.Request) {
	user, ok := a.currentUser(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if user.Role == model.RoleViewer {
		writeError(w, http.StatusForbidden, "analyst or administrator role required")
		return
	}
	if err := a.scanner.Cancel(r.PathValue("id")); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "scan not found")
			return
		}
		if errors.Is(err, scanner.ErrScanNotCancelable) {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		slog.Error("Could not cancel scan", "scan_id", r.PathValue("id"), "error", err)
		writeError(w, http.StatusInternalServerError, "could not cancel scan")
		return
	}
	event := model.AuditEvent{OccurredAt: time.Now().UTC(), ActorID: user.ID, Action: "scan.canceled",
		Severity: model.AuditWarning, TargetType: "scan", TargetID: r.PathValue("id"), SourceIP: requestIP(r), Details: "{}"}
	if err := a.store.AppendAuditEvent(event); err != nil {
		slog.Warn("Scan cancellation audit event could not be persisted", "scan_id", r.PathValue("id"), "error", err)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) createScan(w http.ResponseWriter, r *http.Request) {
	user, ok := a.currentUser(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if user.Role == model.RoleViewer {
		writeError(w, http.StatusForbidden, "analyst or administrator role required")
		return
	}
	var req model.CreateScanRequest
	decoder := json.NewDecoder(io.LimitReader(r.Body, maxRequestBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON request")
		return
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		writeError(w, http.StatusBadRequest, "request must contain exactly one JSON object")
		return
	}
	policy, err := a.requestScopePolicy(req.ScopePolicyID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	targets, ports, err := a.scanner.ValidateWithPolicy(req, policy)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = "Untitled scan"
	}
	if len(name) > maxScanNameLength {
		writeError(w, http.StatusBadRequest, "scan name must be 100 characters or fewer")
		return
	}
	scanID, err := randomID()
	if err != nil {
		slog.Error("Could not generate a scan identifier", "error", err)
		writeError(w, http.StatusInternalServerError, "could not create scan")
		return
	}
	scan := model.Scan{
		ID:            scanID,
		Name:          name,
		Targets:       targets,
		Ports:         ports,
		Status:        model.StatusQueued,
		Observations:  []model.ServiceObservation{},
		Findings:      []model.Finding{},
		CVEMatches:    []model.CVEMatch{},
		TotalChecks:   len(targets) * len(ports),
		CreatedAt:     time.Now().UTC(),
		ScopePolicyID: policy.ID,
		MaxConcurrent: policy.MaxConcurrent,
	}
	if err := a.scanner.Schedule(scan); errors.Is(err, scanner.ErrQueueFull) {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, "could not schedule scan")
		return
	}
	writeJSON(w, http.StatusAccepted, scan)
}

func (a *API) requestScopePolicy(requestedID string) (model.ScopePolicy, error) {
	if requestedID != "" {
		policy, err := a.store.ScopePolicy(requestedID)
		if err != nil || !policy.Enabled {
			return model.ScopePolicy{}, errors.New("scope policy is unavailable")
		}
		return policy, nil
	}
	if policy, err := a.store.ScopePolicy("default"); err == nil && policy.Enabled {
		return policy, nil
	}
	policies, err := a.store.ListScopePolicies(true)
	if err != nil || len(policies) == 0 {
		return model.ScopePolicy{}, errors.New("no enabled scope policy is available")
	}
	return policies[0], nil
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		if requestIsSecure(r) {
			w.Header().Set("Strict-Transport-Security", "max-age=15552000")
		}
		if sensitivePath(r.URL.Path) {
			w.Header().Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

func requestIsSecure(r *http.Request) bool {
	return r.TLS != nil || r.URL.Scheme == "https"
}

func sensitivePath(path string) bool {
	return strings.HasPrefix(path, "/api/auth/") || strings.HasPrefix(path, "/api/admin/") ||
		path == "/setup.html" || path == "/login.html" || path == "/account.html" || path == "/users.html"
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSONStatus(w, status, map[string]string{"error": message})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	writeJSONStatus(w, status, value)
}

func writeJSONStatus(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		slog.Warn("Could not finish writing an HTTP response", "error", err)
	}
}

func randomID() (string, error) {
	value := make([]byte, 12)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}
