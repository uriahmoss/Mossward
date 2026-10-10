package workerapp

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"mossward/internal/model"
)

func TestLoadConfigAppliesSafeDefaults(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "worker.json")
	contents, err := json.Marshal(Config{ServerURL: "https://mossward.example.test", WorkerID: "worker-1",
		CertificateFile: filepath.Join(directory, "worker.crt"), PrivateKeyFile: filepath.Join(directory, "worker.key"),
		CAFile: filepath.Join(directory, "ca.crt"), StateDirectory: filepath.Join(directory, "state"),
		JobSigningPublicKey: base64.RawStdEncoding.EncodeToString(publicKey), AllowedCIDRs: []string{"192.0.2.0/24"},
		AllowedPorts: []int{443}, MaxConcurrent: 2, Capabilities: []model.WorkerCapability{model.WorkerCapabilityTCPConnect}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if config.PollIntervalSeconds != 15 || config.ProbeTimeoutSeconds != 5 || config.OutboxMaximumItems != 10000 || config.OutboxMaximumBytes != 100<<20 {
		t.Fatalf("scanner-worker defaults were not applied: %#v", config)
	}
	worker := config.Worker()
	if worker.ID != "worker-1" || worker.MaxConcurrent != 2 || worker.Capabilities[0] != model.WorkerCapabilityTCPConnect {
		t.Fatalf("scanner-worker identity was not derived: %#v", worker)
	}
}

func TestConfigRejectsUnsafeOrInvalidScope(t *testing.T) {
	publicKey, _, _ := ed25519.GenerateKey(rand.Reader)
	directory := t.TempDir()
	config := Config{ServerURL: "https://mossward.example.test", WorkerID: "worker", CertificateFile: filepath.Join(directory, "worker.crt"),
		PrivateKeyFile: filepath.Join(directory, "worker.key"), CAFile: filepath.Join(directory, "ca.crt"), StateDirectory: filepath.Join(directory, "state"),
		JobSigningPublicKey: base64.RawStdEncoding.EncodeToString(publicKey), AllowedCIDRs: []string{"not-a-network"},
		AllowedPorts: []int{443}, MaxConcurrent: 1, Capabilities: []model.WorkerCapability{model.WorkerCapabilityTCPConnect},
		PollIntervalSeconds: 1, ProbeTimeoutSeconds: 1, OutboxMaximumItems: 1, OutboxMaximumBytes: 1}
	if err := config.Validate(); err == nil {
		t.Fatal("invalid scanner-worker scope was accepted")
	}
	config.AllowedCIDRs = []string{"192.0.2.0/24"}
	if err := config.Validate(); err != nil {
		t.Fatalf("valid configuration rejected: %v", err)
	}
	config.ServerURL = "http://mossward.example.test"
	if err := config.Validate(); err == nil {
		t.Fatal("insecure scanner-worker server URL was accepted")
	}
}
