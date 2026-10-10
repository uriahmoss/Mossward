//go:build windows

package workerapp

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"mossward/internal/privatefs"
)

func TestNativeWindowsWorkerAcceptance(t *testing.T) {
	if os.Getenv("MOSSWARD_TEST_WORKER_WINDOWS_SERVICE") != "1" {
		t.Skip("requires disposable Windows host service-test opt-in")
	}
	if os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		t.Fatal("service rehearsal requires a disposable GitHub-hosted runner")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	install := filepath.Join(os.Getenv("ProgramFiles"), "Mossward Worker")
	dataDirectory := filepath.Join(os.Getenv("ProgramData"), "Mossward", "Worker")
	for _, path := range []string{install, dataDirectory} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("service rehearsal refuses existing destination %s: %v", path, err)
		}
	}
	manager, err := mgr.Connect()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Disconnect() })
	existing, err := manager.OpenService("MosswardWorker")
	if err == nil {
		existing.Close()
		t.Fatal("service rehearsal refuses an existing worker service")
	}
	if !errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		t.Fatalf("cannot establish absence of worker service: %v", err)
	}
	config, controller, lease := deploymentFixture(t)
	sources := []string{config.CertificateFile, config.PrivateKeyFile, config.CAFile}
	identity := filepath.Join(dataDirectory, "identity")
	config.CertificateFile = filepath.Join(identity, "worker.crt")
	config.PrivateKeyFile = filepath.Join(identity, "worker.key")
	config.CAFile = filepath.Join(identity, "ca.crt")
	config.StateDirectory = filepath.Join(dataDirectory, "state")
	input := filepath.Join(t.TempDir(), "worker.json")
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := privatefs.WriteFile(input, data); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "mossward-worker.exe")
	nativeCommand(t, root, "go", "build", "-o", binary, "./cmd/mossward-worker")
	installedBinary := filepath.Join(install, "mossward-worker.exe")
	t.Cleanup(func() {
		service, err := manager.OpenService("MosswardWorker")
		if err != nil {
			return // Installer may already have rolled back service creation.
		}
		defer service.Close()
		status, err := service.Query()
		if err != nil {
			t.Errorf("query service during cleanup: %v", err)
			return
		}
		if status.State != svc.Stopped {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			output, stopErr := exec.CommandContext(ctx, installedBinary, "service", "stop").CombinedOutput()
			cancel()
			if stopErr != nil {
				t.Errorf("service cleanup stop failed: %v: %s", stopErr, output)
				return
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		output, err := exec.CommandContext(ctx, installedBinary, "service", "uninstall").CombinedOutput()
		cancel()
		if err != nil {
			t.Errorf("service cleanup uninstall failed: %v: %s", err, output)
		}
		// Retain secured identity/state for diagnostics until runner disposal.
	})
	nativeCommand(t, root, "pwsh", "-NoProfile", "-File", "scripts/Test-WorkerInstallation.ps1", "-Binary", binary, "-Configuration", input,
		"-Certificate", sources[0], "-PrivateKey", sources[1], "-CA", sources[2])
	service, err := manager.OpenService("MosswardWorker")
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	serviceConfig, err := service.Config()
	if err != nil || serviceConfig.ServiceStartName != `NT SERVICE\MosswardWorker` {
		t.Fatalf("unexpected service identity: %q, %v", serviceConfig.ServiceStartName, err)
	}
	nativeCommand(t, root, installedBinary, "service", "start")
	waitNativeCompletion(t, controller)
	nativeCommand(t, root, installedBinary, "service", "stop")
	controller.mu.Lock()
	controller.lease = lease
	controller.mu.Unlock()
	nativeCommand(t, root, installedBinary, "service", "start")
	deadline := time.Now().Add(nativeServiceAcceptanceTimeout)
	for time.Now().Before(deadline) {
		controller.mu.Lock()
		consumed := controller.lease.Envelope.Job.ID == ""
		controller.mu.Unlock()
		if consumed {
			nativeCommand(t, root, installedBinary, "service", "stop")
			assertNativeReplayRejected(t, controller)
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("restarted Windows worker did not poll replayed job")
}
