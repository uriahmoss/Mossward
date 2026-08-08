package agentapp

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"mossward/internal/model"
)

func TestSaveIdentityUsesPrivatePermissions(t *testing.T) {
	directory := t.TempDir()
	endpoint := model.Endpoint{ID: "endpoint-1", ExpiresAt: time.Now().Add(time.Hour)}
	if err := saveIdentity(directory, []byte("key"), []byte("certificate"), []byte("CA"), endpoint); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"agent-key.pem", "agent-cert.pem", "agent-ca.pem", "identity.json"} {
		path := filepath.Join(directory, name)
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
			t.Errorf("%s permissions = %o, want 600", name, info.Mode().Perm())
		}
	}
}

func TestRequirePrivatePermissionsRejectsBroadKey(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows permissions are enforced through ACLs")
	}
	path := filepath.Join(t.TempDir(), "agent-key.pem")
	if err := os.WriteFile(path, []byte("key"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := requirePrivatePermissions(path); err == nil {
		t.Fatal("broad private-key permissions were accepted")
	}
}

func TestRetryDelayIsBoundedByCheckInInterval(t *testing.T) {
	interval := 60 * time.Second
	if delay := retryDelay(interval, 1); delay != 2*time.Second {
		t.Fatalf("first retry delay = %s", delay)
	}
	if delay := retryDelay(interval, 20); delay != interval {
		t.Fatalf("bounded retry delay = %s", delay)
	}
}
