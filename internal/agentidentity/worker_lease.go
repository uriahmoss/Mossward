package agentidentity

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"mossward/internal/model"
	"mossward/internal/store"
)

const workerLeaseRenewalBodyLimit = 8 << 10

func (s *Service) workerRenewJobLease(w http.ResponseWriter, r *http.Request) {
	worker, err := s.workerFromConnection(r.TLS)
	if err != nil {
		http.Error(w, "authenticated scanner worker required", http.StatusUnauthorized)
		return
	}
	var request model.WorkerJobLeaseRenewal
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, workerLeaseRenewalBodyLimit))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil || decoder.Decode(&struct{}{}) != io.EOF || strings.TrimSpace(request.JobID) == "" {
		http.Error(w, "invalid scanner-worker lease renewal", http.StatusBadRequest)
		return
	}
	hash, err := workerLeaseTokenHash(request.LeaseToken)
	if err != nil {
		http.Error(w, "invalid scanner-worker lease renewal", http.StatusBadRequest)
		return
	}
	now := s.now()
	expiresAt, err := s.workerStore.RenewScannerWorkerJobLease(worker.ID, request.JobID, hash, now, now.Add(workerJobLeaseLifetime))
	if errors.Is(err, store.ErrInvalidWorkerJobLease) {
		http.Error(w, "scanner-worker job lease is invalid or expired", http.StatusConflict)
		return
	}
	if err != nil {
		http.Error(w, "scanner-worker job lease renewal unavailable", http.StatusServiceUnavailable)
		return
	}
	request.ExpiresAt = expiresAt
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(request)
}
