package linuxdeployment

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type serverFixture struct {
	root, script, binary, config string
	environment                  []string
}

func TestServerInstallUninstallReinstallPreservesState(t *testing.T) {
	f := newServerFixture(t)
	f.run(t, true, "install", f.binary, f.config)
	state := filepath.Join(f.root, "var/lib/mossward", "keep.db")
	writeFixture(t, state, "retained state", 0600)
	f.run(t, false, "install", f.binary, f.config)
	f.run(t, true, "uninstall")
	data, err := os.ReadFile(state)
	if err != nil || string(data) != "retained state" {
		t.Fatal("uninstall changed state", err)
	}
	if _, err := os.Stat(filepath.Join(f.root, "etc/mossward/mossward.env")); err != nil {
		t.Fatal("uninstall removed configuration", err)
	}
	f.run(t, true, "install", f.binary)
	if _, err := os.Stat(filepath.Join(f.root, "usr/local/bin/mossward")); err != nil {
		t.Fatal("reinstall did not restore executable", err)
	}
}

func TestServerRejectsSymlinksAndUnmanagedRemoval(t *testing.T) {
	f := newServerFixture(t)
	f.run(t, false, "uninstall")
	link := filepath.Join(f.root, "linked-binary")
	if err := os.Symlink(f.binary, link); err != nil {
		t.Fatal(err)
	}
	f.run(t, false, "install", link, f.config)
	if err := os.Symlink(t.TempDir(), filepath.Join(f.root, "etc/mossward")); err != nil {
		t.Fatal(err)
	}
	f.run(t, false, "install", f.binary, f.config)
}

func TestServerUpdateFailureStopsServiceAndPreservesRecoveryBinary(t *testing.T) {
	f := newServerFixture(t)
	f.run(t, true, "install", f.binary, f.config)
	backup := filepath.Join(f.root, "backup.tar.gz")
	writeFixture(t, backup, "synthetic backup", 0600)
	f.environment = append(f.environment, "MOCK_SERVICE_ACTIVE=active")
	f.run(t, false, "update", f.binary, "--backup", backup, "--confirm-current-offline-backup")
	f.environment[len(f.environment)-1] = "MOCK_SERVICE_ACTIVE=inactive"
	f.environment = append(f.environment, "MOCK_CURL_FAIL=1")
	f.run(t, false, "update", f.binary, "--backup", backup, "--confirm-current-offline-backup")
	trace, err := os.ReadFile(filepath.Join(f.root, "trace"))
	if err != nil || !strings.Contains(string(trace), "stop mossward.service") {
		t.Fatal("readiness failure did not stop service", err)
	}
	if _, err := os.Stat(filepath.Join(f.root, "etc/mossward/mossward.previous")); err != nil {
		t.Fatal("readiness failure removed recovery binary", err)
	}
}

func TestServerUpdateRequiresVerifiedBackupAndRetainsPriorBinary(t *testing.T) {
	f := newServerFixture(t)
	f.run(t, true, "install", f.binary, f.config)
	backup := filepath.Join(f.root, "backup.tar.gz")
	writeFixture(t, backup, "synthetic backup", 0600)
	f.run(t, false, "update", f.binary)
	f.environment = append(f.environment, "MOCK_BACKUP_FAIL=1")
	f.run(t, false, "update", f.binary, "--backup", backup, "--confirm-current-offline-backup")
	if _, err := os.Stat(filepath.Join(f.root, "etc/mossward/mossward.previous")); !os.IsNotExist(err) {
		t.Fatal("failed backup verification changed deployment")
	}
	f.environment[len(f.environment)-1] = "MOCK_BACKUP_FAIL=0"
	f.run(t, true, "update", f.binary, "--backup", backup, "--confirm-current-offline-backup")
	if _, err := os.Stat(filepath.Join(f.root, "etc/mossward/mossward.previous")); err != nil {
		t.Fatal("update did not retain prior binary", err)
	}
	f.run(t, false, "update", f.binary, "--backup", backup, "--confirm-current-offline-backup")
}

func newServerFixture(t *testing.T) serverFixture {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell orchestration fixtures require POSIX tools")
	}
	root := t.TempDir()
	for _, path := range []string{"usr/local/bin", "etc/systemd/system", "var/lib", "run", "mockbin"} {
		if err := os.MkdirAll(filepath.Join(root, path), 0755); err != nil {
			t.Fatal(err)
		}
	}
	source, err := os.ReadFile("../../deploy/linux/manage-mossward-server.sh")
	if err != nil {
		t.Fatal(err)
	}
	// Redirect exact production roots in a test-only copy, never in the shipped tool.
	script := strings.NewReplacer("/usr/local", root+"/usr/local", "/etc", root+"/etc", "/var/lib", root+"/var/lib", "/run", root+"/run", " /usr ", " "+root+"/usr ", " /var ", " "+root+"/var ").Replace(string(source))
	script = strings.ReplaceAll(script, "env -i PATH=/usr/bin:/bin", "env")
	f := serverFixture{root: root, script: filepath.Join(root, "manage.sh"), binary: filepath.Join(root, "input-binary"), config: filepath.Join(root, "input.env")}
	writeFixture(t, f.script, script, 0700)
	writeFixture(t, filepath.Join(root, "mossward.service"), "synthetic unit", 0600)
	writeFixture(t, f.binary, "#!/bin/sh\n[ \"${MOCK_BACKUP_FAIL:-0}\" = 0 ]\n", 0700)
	writeFixture(t, f.config, "MOSSWARD_TRANSPORT_MODE=local\n", 0600)
	commands := map[string]string{
		"id":       "echo 0",
		"stat":     "case \"$2\" in %u) echo 0 ;; %a) echo 755 ;; esac",
		"getent":   "exit 1",
		"groupadd": "exit 0", "useradd": "exit 0", "curl": "[ \"${MOCK_CURL_FAIL:-0}\" = 0 ]", "flock": "exit 0", "sleep": "exit 0",
		"systemctl": "echo \"$*\" >> \"$MOCK_TRACE\"; if [ \"$1\" = show ]; then echo \"${MOCK_SERVICE_ACTIVE:-inactive}\"; fi",
		"install":   "if [ \"$1\" = -d ]; then shift; shift 4; [ \"$1\" = -m ] && shift 2; mkdir -p \"$1\"; exit; fi; shift 4; exec /usr/bin/install \"$@\"",
	}
	for name, body := range commands {
		writeFixture(t, filepath.Join(root, "mockbin", name), "#!/bin/sh\n"+body+"\n", 0700)
	}
	f.environment = append(os.Environ(), "PATH="+filepath.Join(root, "mockbin")+":"+os.Getenv("PATH"), "MOCK_TRACE="+filepath.Join(root, "trace"))
	return f
}

func writeFixture(t *testing.T, path, contents string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), mode); err != nil {
		t.Fatal(err)
	}
}

func (f serverFixture) run(t *testing.T, success bool, args ...string) {
	t.Helper()
	command := exec.Command("sh", append([]string{f.script}, args...)...)
	command.Env = f.environment
	output, err := command.CombinedOutput()
	if (err == nil) != success {
		t.Fatalf("unexpected lifecycle outcome: %v: %s", err, output)
	}
}
