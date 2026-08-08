package agentidentity

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"mossward/internal/model"
	"mossward/internal/store"
	"mossward/internal/workerevidence"
)

const workerEvidenceRequestLimit = (1 << 20) + (64 << 10)

func (s *Service) workerSubmitEvidence(w http.ResponseWriter, r *http.Request) {
	worker, err := s.workerFromConnection(r.TLS)
	if err != nil {
		http.Error(w, "authenticated scanner worker required", http.StatusUnauthorized)
		return
	}
	var envelope model.SignedWorkerEvidenceBatch
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, workerEvidenceRequestLimit))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		http.Error(w, "invalid scanner-worker evidence batch", http.StatusBadRequest)
		return
	}
	jobEnvelope, err := s.workerStore.ScannerWorkerJob(envelope.Batch.JobID)
	if err != nil || jobEnvelope.Job.WorkerID != worker.ID {
		http.Error(w, "scanner-worker evidence job is unavailable", http.StatusConflict)
		return
	}
	now := s.now()
	if err := workerevidence.VerifyForJob(envelope, r.TLS.PeerCertificates[0], jobEnvelope.Job, now); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.workerStore.RecordScannerWorkerEvidenceBatch(envelope, now); err != nil {
		if errors.Is(err, store.ErrWorkerEvidenceAlreadyAccepted) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "already_accepted", "batch_id": envelope.Batch.ID, "sequence": envelope.Batch.Sequence})
			return
		}
		if errors.Is(err, store.ErrWorkerEvidenceReplay) || errors.Is(err, store.ErrWorkerEvidenceSequence) || errors.Is(err, store.ErrInvalidWorkerJobLease) {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		slog.Error("Could not record scanner-worker evidence batch", "worker_id", worker.ID, "job_id", envelope.Batch.JobID, "batch_id", envelope.Batch.ID, "error", err)
		http.Error(w, "scanner-worker evidence storage unavailable", http.StatusServiceUnavailable)
		return
	}
	slog.Info("Scanner-worker evidence batch accepted", "worker_id", worker.ID, "job_id", envelope.Batch.JobID,
		"batch_id", envelope.Batch.ID, "sequence", envelope.Batch.Sequence, "final", envelope.Batch.Final)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "accepted", "batch_id": envelope.Batch.ID, "sequence": envelope.Batch.Sequence})
}
