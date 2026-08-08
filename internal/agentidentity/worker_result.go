package agentidentity

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"mossward/internal/model"
	"mossward/internal/store"
)

const (
	workerResultSchemaVersion = 1
	workerResultBodyLimit     = 8 << 10
	workerResultIDLimit       = 200
	workerResultClockSkew     = time.Minute
)

func (s *Service) workerSubmitResult(w http.ResponseWriter, r *http.Request) {
	worker, err := s.workerFromConnection(r.TLS)
	if err != nil {
		http.Error(w, "authenticated scanner worker required", http.StatusUnauthorized)
		return
	}
	var result model.WorkerJobResult
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, workerResultBodyLimit))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		http.Error(w, "invalid scanner-worker result", http.StatusBadRequest)
		return
	}
	now := s.now()
	if err := validateWorkerJobResult(result, now); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	tokenHash, err := workerLeaseTokenHash(result.LeaseToken)
	if err != nil {
		http.Error(w, "invalid scanner-worker result", http.StatusBadRequest)
		return
	}
	receipt := model.WorkerJobResultReceipt{ResultID: result.ID, JobID: result.JobID, WorkerID: worker.ID,
		Outcome: result.Outcome, CompletedAt: result.CompletedAt, AcceptedAt: now}
	if err := s.workerStore.CompleteScannerWorkerJob(receipt, tokenHash, now); err != nil {
		if errors.Is(err, store.ErrWorkerResultAlreadyAccepted) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(receipt)
			return
		}
		if errors.Is(err, store.ErrWorkerResultReplay) {
			http.Error(w, "scanner-worker result was already submitted", http.StatusConflict)
			return
		}
		if errors.Is(err, store.ErrInvalidWorkerJobLease) {
			http.Error(w, "scanner-worker job lease is invalid or expired", http.StatusConflict)
			return
		}
		slog.Error("Could not accept scanner-worker result", "worker_id", worker.ID, "job_id", result.JobID, "error", err)
		http.Error(w, "scanner-worker result storage unavailable", http.StatusServiceUnavailable)
		return
	}
	slog.Info("Scanner-worker result accepted", "worker_id", worker.ID, "job_id", result.JobID, "result_id", result.ID, "outcome", result.Outcome)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(receipt)
}

func validateWorkerJobResult(result model.WorkerJobResult, now time.Time) error {
	if result.SchemaVersion != workerResultSchemaVersion {
		return errors.New("unsupported scanner-worker result schema")
	}
	if strings.TrimSpace(result.ID) == "" || len(result.ID) > workerResultIDLimit || strings.TrimSpace(result.JobID) == "" || len(result.JobID) > workerResultIDLimit {
		return errors.New("scanner-worker result identifiers are invalid")
	}
	if result.Outcome != model.WorkerJobResultSucceeded && result.Outcome != model.WorkerJobResultFailed && result.Outcome != model.WorkerJobResultCanceled {
		return errors.New("scanner-worker result outcome is invalid")
	}
	if result.CompletedAt.IsZero() || result.CompletedAt.After(now.Add(workerResultClockSkew)) {
		return errors.New("scanner-worker completion time is invalid")
	}
	return nil
}

func workerLeaseTokenHash(token string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != workerJobLeaseBytes {
		return nil, errors.New("invalid scanner-worker lease token")
	}
	hash := sha256.Sum256([]byte(token))
	return hash[:], nil
}
