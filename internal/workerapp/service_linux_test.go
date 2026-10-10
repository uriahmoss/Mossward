//go:build linux

package workerapp

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"mossward/internal/model"
	"mossward/internal/privatefs"
)

// This explicitly opted-in test owns a fresh installation on a disposable host.
// Never run it on an existing Mossward installation or a production machine.
func TestNativeSystemdWorkerAcceptance(t *testing.T) {
	if os.Getenv("MOSSWARD_TEST_WORKER_SYSTEMD") != "1" {
		t.Skip("requires explicit disposable Linux host service-test opt-in")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/etc/mossward-worker", "/var/lib/mossward-worker", "/usr/local/bin/mossward-worker", "/etc/systemd/system/mossward-worker.service"} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("service rehearsal requires absent destination %s: %v", path, err)
		}
	}
	if exec.Command("getent", "passwd", "mossward-worker").Run() == nil {
		t.Fatal("service rehearsal refuses an existing worker account")
	}
	config, controller, lease := deploymentFixture(t)
	sources := []string{config.CertificateFile, config.PrivateKeyFile, config.CAFile}
	config.CertificateFile = "/etc/mossward-worker/worker.crt"
	config.PrivateKeyFile = "/etc/mossward-worker/worker.key"
	config.CAFile = "/etc/mossward-worker/ca.crt"
	config.StateDirectory = "/var/lib/mossward-worker"
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(t.TempDir(), "worker.json")
	if err := privatefs.WriteFile(input, data); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "mossward-worker")
	nativeCommand(t, root, "go", "build", "-o", binary, "./cmd/mossward-worker")
	// Cleanup only the exact installation files this test owns. Private state
	// and the service account remain for diagnostics until the runner is discarded.
	t.Cleanup(func() {
		for _, args := range [][]string{
			{"systemctl", "stop", "mossward-worker.service"},
			{"rm", "-f", "/etc/systemd/system/mossward-worker.service", "/usr/local/bin/mossward-worker", "/etc/mossward-worker/worker.json", "/etc/mossward-worker/worker.crt", "/etc/mossward-worker/worker.key", "/etc/mossward-worker/ca.crt"},
			{"systemctl", "daemon-reload"},
		} {
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
			output, err := exec.CommandContext(ctx, "sudo", append([]string{"-n"}, args...)...).CombinedOutput()
			cancel()
			if err != nil {
				t.Errorf("service cleanup failed: %v: %s", err, output)
			}
		}
	})
	nativeCommand(t, root, "sudo", "-n", "sh", "deploy/linux/install-mossward-worker.sh", binary, input)
	for index, destination := range []string{config.CertificateFile, config.PrivateKeyFile, config.CAFile} {
		owner, mode := "root", "0640"
		if index == 1 {
			owner, mode = "mossward-worker", "0400"
		}
		nativeCommand(t, root, "sudo", "-n", "install", "-o", owner, "-g", "mossward-worker", "-m", mode, sources[index], destination)
	}
	nativeCommand(t, root, "sudo", "-n", "runuser", "-u", "mossward-worker", "--", "/usr/local/bin/mossward-worker", "--config", "/etc/mossward-worker/worker.json", "--check-config")
	nativeCommand(t, root, "sudo", "-n", "systemctl", "start", "mossward-worker.service")
	waitNativeCompletion(t, controller)
	nativeCommand(t, root, "sudo", "-n", "systemctl", "is-active", "--quiet", "mossward-worker.service")
	nativeCommand(t, root, "sudo", "-n", "systemctl", "stop", "mossward-worker.service")
	controller.mu.Lock()
	controller.lease = lease
	controller.mu.Unlock()
	nativeCommand(t, root, "sudo", "-n", "systemctl", "start", "mossward-worker.service")
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		controller.mu.Lock()
		consumed := controller.lease.Envelope.Job.ID == ""
		evidence, results := len(controller.evidence), len(controller.results)
		controller.mu.Unlock()
		if evidence != 1 || results != 1 {
			t.Fatal("service restart repeated evidence or completion for a replayed job")
		}
		if consumed {
			nativeCommand(t, root, "sudo", "-n", "systemctl", "stop", "mossward-worker.service")
			controller.mu.Lock()
			defer controller.mu.Unlock()
			if len(controller.evidence) != 1 || len(controller.results) != 1 {
				t.Fatal("replayed job produced duplicate delivery before shutdown")
			}
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("restarted service did not poll the replayed job")
}

func nativeCommand(t *testing.T, directory, name string, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, name, args...)
	command.Dir = directory
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("native service command %s failed: %v: %s", name, err, output)
	}
}

func waitNativeCompletion(t *testing.T, controller *deploymentController) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		controller.mu.Lock()
		complete := len(controller.evidence) == 1 && len(controller.results) == 1
		if complete && controller.results[0].Outcome != model.WorkerJobResultSucceeded {
			controller.mu.Unlock()
			t.Fatal("native service scan did not succeed")
		}
		controller.mu.Unlock()
		if complete {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("native worker did not deliver signed scan evidence and completion")
}
