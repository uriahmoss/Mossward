package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"mossward/internal/config"
	"mossward/internal/model"
	"mossward/internal/scanner"
	"mossward/internal/store"
	"mossward/web"
)

type API struct {
	cfg     config.Config
	store   *store.FileStore
	scanner *scanner.Engine
}

func New(cfg config.Config, repository *store.FileStore, engine *scanner.Engine) http.Handler {
	api := &API{cfg: cfg, store: repository, scanner: engine}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", api.health)
	mux.HandleFunc("GET /api/config", api.getConfig)
	mux.HandleFunc("GET /api/scans", api.listScans)
	mux.HandleFunc("POST /api/scans", api.createScan)
	mux.HandleFunc("GET /api/scans/{id}", api.getScan)
	mux.Handle("/", http.FileServer(http.FS(web.Files)))
	return securityHeaders(mux)
}

func (a *API) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
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
	writeJSON(w, http.StatusOK, a.store.List())
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

func (a *API) createScan(w http.ResponseWriter, r *http.Request) {
	var req model.CreateScanRequest
	decoder := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON request")
		return
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		writeError(w, http.StatusBadRequest, "request must contain exactly one JSON object")
		return
	}
	targets, ports, err := a.scanner.Validate(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = "Untitled scan"
	}
	if len(name) > 100 {
		writeError(w, http.StatusBadRequest, "scan name must be 100 characters or fewer")
		return
	}
	scan := model.Scan{
		ID:          randomID(),
		Name:        name,
		Targets:     targets,
		Ports:       ports,
		Status:      model.StatusQueued,
		Findings:    []model.Finding{},
		TotalChecks: len(targets) * len(ports),
		CreatedAt:   time.Now().UTC(),
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

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
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
	_ = json.NewEncoder(w).Encode(value)
}

func randomID() string {
	value := make([]byte, 12)
	_, _ = rand.Read(value)
	return hex.EncodeToString(value)
}
