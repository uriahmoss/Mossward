package agentidentity

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"mossward/internal/model"
	"mossward/internal/store"
)

const (
	workerJobLeaseLifetime = 2 * time.Minute
	workerJobLeaseBytes    = 32
)

func (s *Service) workerPollJob(w http.ResponseWriter, r *http.Request) {
	worker, err := s.workerFromConnection(r.TLS)
	if err != nil {
		http.Error(w, "authenticated scanner worker required", http.StatusUnauthorized)
		return
	}
	token, hash, err := newWorkerJobLeaseToken()
	if err != nil {
		slog.Error("Could not create scanner-worker job lease token", "worker_id", worker.ID, "error", err)
		http.Error(w, "scanner-worker job queue unavailable", http.StatusServiceUnavailable)
		return
	}
	now := s.now()
	leaseExpiresAt := now.Add(workerJobLeaseLifetime)
	envelope, err := s.workerStore.LeaseScannerWorkerJob(worker.ID, hash, now, leaseExpiresAt)
	if errors.Is(err, store.ErrNotFound) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		slog.Error("Could not lease scanner-worker job", "worker_id", worker.ID, "error", err)
		http.Error(w, "scanner-worker job queue unavailable", http.StatusServiceUnavailable)
		return
	}
	if envelope.Job.ExpiresAt.Before(leaseExpiresAt) {
		leaseExpiresAt = envelope.Job.ExpiresAt
	}
	slog.Info("Scanner-worker job leased", "worker_id", worker.ID, "job_id", envelope.Job.ID, "lease_expires_at", leaseExpiresAt)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(model.WorkerJobLease{Envelope: envelope, Token: token, ExpiresAt: leaseExpiresAt})
}

func newWorkerJobLeaseToken() (string, []byte, error) {
	raw := make([]byte, workerJobLeaseBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256([]byte(token))
	return token, hash[:], nil
}
