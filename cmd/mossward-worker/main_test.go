package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWorkerCLIRejectsMissingRelativeAndTrailingConfiguration(t *testing.T) {
	t.Setenv("MOSSWARD_WORKER_CONFIG", "")
	for _, args := range [][]string{nil, {"--config", "relative.json"}, {"--config", "/missing/worker.json", "unexpected"}} {
		if err := runArguments(args); err == nil {
			t.Fatalf("invalid arguments accepted: %v", args)
		}
	}
}

func TestCheckConfigDoesNotCreateState(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "worker.json")
	if err := os.WriteFile(path, []byte(`{"server_url":"http://insecure.example"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runArguments([]string{"--config", path, "--check-config"}); err == nil {
		t.Fatal("invalid configuration accepted")
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 1 {
		t.Fatal("preflight changed filesystem")
	}
}
