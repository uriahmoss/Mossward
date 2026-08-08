package agentapp

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigAppliesSafeDefaults(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "agent.json")
	contents := `{"server_url":"https://mossward.example.test","endpoint_url":"https://agents.example.test:9443","state_directory":"` + directory + `"}`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if config.CheckInIntervalSeconds != 60 {
		t.Fatalf("interval = %d", config.CheckInIntervalSeconds)
	}
}
func TestConfigRejectsInboundOrInsecureOrigins(t *testing.T) {
	config := Config{ServerURL: "http://mossward.example.test", EndpointURL: "https://agents.example.test", StateDirectory: t.TempDir(), CheckInIntervalSeconds: 60}
	if err := config.Validate(); err == nil {
		t.Fatal("insecure server URL was accepted")
	}
	config.ServerURL = "https://mossward.example.test/path"
	if err := config.Validate(); err == nil {
		t.Fatal("server URL path was accepted")
	}
}
