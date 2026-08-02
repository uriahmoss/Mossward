package workerevidence

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/netip"
	"time"

	"mossward/internal/model"
)

const (
	evidenceSchemaVersion = 1
	maximumEvidenceItems  = 250
	maximumEvidenceBytes  = 1 << 20
	evidenceIdentityLimit = 200
	evidenceClockSkew     = time.Minute
)

func VerifyForJob(envelope model.SignedWorkerEvidenceBatch, certificate *x509.Certificate, job model.WorkerJob, now time.Time) error {
	if certificate == nil || now.Before(certificate.NotBefore) || now.After(certificate.NotAfter) || certificate.KeyUsage&x509.KeyUsageDigitalSignature == 0 || !certificateMatchesWorker(certificate, job.WorkerID) {
		return errors.New("worker evidence certificate is not valid for this worker")
	}
	if err := Verify(envelope, certificate); err != nil {
		return err
	}
	return Validate(envelope.Batch, job, now)
}

func certificateMatchesWorker(certificate *x509.Certificate, workerID string) bool {
	wanted := "spiffe://mossward/scanner-worker/" + workerID
	for _, identity := range certificate.URIs {
		if identity.String() == wanted {
			return true
		}
	}
	return false
}

func Validate(batch model.WorkerEvidenceBatch, job model.WorkerJob, now time.Time) error {
	if batch.SchemaVersion != evidenceSchemaVersion || batch.Sequence == 0 {
		return errors.New("worker evidence schema or sequence is invalid")
	}
	if !validEvidenceIdentities(batch, job) {
		return errors.New("worker evidence identity is invalid")
	}
	if batch.CollectedAt.IsZero() || batch.CollectedAt.Before(job.IssuedAt.Add(-evidenceClockSkew)) || batch.CollectedAt.After(now.Add(evidenceClockSkew)) {
		return errors.New("worker evidence collection time is invalid")
	}
	itemCount := len(batch.Observations) + len(batch.Findings) + len(batch.Checkpoints)
	if itemCount == 0 && !batch.Final {
		return errors.New("non-final worker evidence batch is empty")
	}
	if itemCount > maximumEvidenceItems {
		return errors.New("worker evidence batch contains too many items")
	}
	encoded, err := json.Marshal(batch)
	if err != nil || len(encoded) > maximumEvidenceBytes {
		return errors.New("worker evidence batch exceeds its encoded size limit")
	}
	return validateEvidenceItems(batch, job)
}

func validEvidenceIdentities(batch model.WorkerEvidenceBatch, job model.WorkerJob) bool {
	return batch.ID != "" && len(batch.ID) <= evidenceIdentityLimit && batch.WorkerID == job.WorkerID &&
		batch.JobID == job.ID && batch.ScanID == job.ScanID
}

func validateEvidenceItems(batch model.WorkerEvidenceBatch, job model.WorkerJob) error {
	targets := map[netip.Addr]bool{}
	for _, target := range job.Targets {
		address, _ := netip.ParseAddr(target.Address)
		targets[address] = true
	}
	ports := map[int]bool{}
	for _, port := range job.Ports {
		ports[port] = true
	}
	identities := map[string]bool{}
	for _, observation := range batch.Observations {
		if !validEvidenceItem(observation.ID, observation.Address, observation.Port, observation.ObservedAt, job.IssuedAt, batch.CollectedAt, targets, ports, identities) {
			return errors.New("worker observation is duplicate, invalid, or outside its job")
		}
	}
	for _, finding := range batch.Findings {
		if !validEvidenceItem(finding.ID, finding.Address, finding.Port, finding.ObservedAt, job.IssuedAt, batch.CollectedAt, targets, ports, identities) {
			return errors.New("worker finding is duplicate, invalid, or outside its job")
		}
	}
	checkpoints := map[netip.AddrPort]bool{}
	for _, checkpoint := range batch.Checkpoints {
		address, err := netip.ParseAddr(checkpoint.Address)
		if err != nil || checkpoint.Port < 1 || checkpoint.Port > 65535 {
			return errors.New("worker checkpoint is duplicate, invalid, or outside its job")
		}
		key := netip.AddrPortFrom(address, uint16(checkpoint.Port))
		if checkpoints[key] || !targets[address] || !ports[checkpoint.Port] || checkpoint.CompletedAt.IsZero() ||
			checkpoint.CompletedAt.Before(job.IssuedAt.Add(-evidenceClockSkew)) || checkpoint.CompletedAt.After(batch.CollectedAt.Add(evidenceClockSkew)) {
			return errors.New("worker checkpoint is duplicate, invalid, or outside its job")
		}
		checkpoints[key] = true
	}
	return nil
}

func validEvidenceItem(id, rawAddress string, port int, observedAt, issuedAt, collectedAt time.Time, targets map[netip.Addr]bool, ports map[int]bool, identities map[string]bool) bool {
	address, err := netip.ParseAddr(rawAddress)
	if err != nil || id == "" || len(id) > evidenceIdentityLimit || identities[id] || !targets[address] || !ports[port] {
		return false
	}
	if observedAt.IsZero() || observedAt.Before(issuedAt.Add(-evidenceClockSkew)) || observedAt.After(collectedAt.Add(evidenceClockSkew)) {
		return false
	}
	identities[id] = true
	return true
}
