package workerevidence

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"math/big"
	"net/url"
	"testing"
	"time"

	"mossward/internal/model"
)

func TestWorkerEvidenceSignatureAndJobBinding(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	batch, job := evidenceFixture(now)
	certificate, key := evidenceCertificate(t, job.WorkerID, now, false)
	envelope, err := Sign(batch, certificate, key)
	if err != nil || VerifyForJob(envelope, certificate, job, now) != nil {
		t.Fatalf("valid worker evidence did not verify: %v", err)
	}
	envelope.Batch.Observations[0].Port = 22
	if err := VerifyForJob(envelope, certificate, job, now); err == nil {
		t.Fatal("tampered worker evidence signature was accepted")
	}
}

func TestWorkerEvidenceSupportsRSAPSS(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	batch, job := evidenceFixture(now)
	certificate, key := evidenceCertificate(t, job.WorkerID, now, true)
	envelope, err := Sign(batch, certificate, key)
	if err != nil || envelope.Algorithm != algorithmRSAPSSSHA256 || VerifyForJob(envelope, certificate, job, now) != nil {
		t.Fatalf("RSA-PSS worker evidence did not verify: %#v %v", envelope, err)
	}
}

func TestWorkerEvidenceRejectsOutOfScopeAndDuplicateItems(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	batch, job := evidenceFixture(now)
	batch.Observations[0].Address = "198.51.100.10"
	if err := Validate(batch, job, now); err == nil {
		t.Fatal("out-of-scope worker evidence was accepted")
	}
	batch, job = evidenceFixture(now)
	batch.Findings = []model.Finding{{ID: batch.Observations[0].ID, Address: "192.0.2.10", Port: 443, ObservedAt: now}}
	if err := Validate(batch, job, now); err == nil {
		t.Fatal("duplicate worker evidence identity was accepted")
	}
	batch, job = evidenceFixture(now)
	batch.Checkpoints[0].Port = 22
	if err := Validate(batch, job, now); err == nil {
		t.Fatal("out-of-scope worker checkpoint was accepted")
	}
	batch, job = evidenceFixture(now)
	batch.Checkpoints = append(batch.Checkpoints, batch.Checkpoints[0])
	if err := Validate(batch, job, now); err == nil {
		t.Fatal("duplicate worker checkpoint was accepted")
	}
}

func evidenceFixture(now time.Time) (model.WorkerEvidenceBatch, model.WorkerJob) {
	job := model.WorkerJob{ID: "job", WorkerID: "worker", ScanID: "scan", IssuedAt: now.Add(-time.Minute),
		ExpiresAt: now.Add(5 * time.Minute), Targets: []model.Target{{Name: "host", Address: "192.0.2.10"}}, Ports: []int{443}}
	batch := model.WorkerEvidenceBatch{SchemaVersion: 1, ID: "batch", WorkerID: job.WorkerID, JobID: job.ID,
		ScanID: job.ScanID, Sequence: 1, CollectedAt: now,
		Observations: []model.ServiceObservation{{ID: "observation", Target: "host", Address: "192.0.2.10", Port: 443,
			Protocol: "https", Confidence: "high", Evidence: "reachable", ObservedAt: now}},
		Checkpoints: []model.WorkerCheckpoint{{Address: "192.0.2.10", Port: 443, CompletedAt: now}}}
	return batch, job
}

func evidenceCertificate(t *testing.T, workerID string, now time.Time, useRSA bool) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	var signer crypto.Signer
	var err error
	if useRSA {
		signer, err = rsa.GenerateKey(rand.Reader, 2048)
	} else {
		signer, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if err != nil {
		t.Fatal(err)
	}
	identity, _ := url.Parse("spiffe://mossward/scanner-worker/" + workerID)
	template := &x509.Certificate{SerialNumber: big.NewInt(42), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		URIs: []*url.URL{identity}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, signer
}
