package postgresverify

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestParseMajor(t *testing.T) {
	for _, test := range []struct {
		version  string
		expected int
		valid    bool
	}{
		{"postgres (PostgreSQL) 16.15", 16, true},
		{"postgres (PostgreSQL) 17.11", 0, true},
		{"postgres (PostgreSQL) 13.1", 0, false},
		{"postgres (PostgreSQL) 14.24", 16, false},
		{"unknown", 0, false},
	} {
		_, err := parseMajor(test.version, test.expected)
		if (err == nil) != test.valid {
			t.Errorf("version %q: %v", test.version, err)
		}
	}
}

func TestEnvironmentDropsInheritedDatabaseAndApplicationSettings(t *testing.T) {
	input := []string{"PATH=bin", "PGPASSWORD=secret", "pgservice=production", "MOSSWARD_TEST_POSTGRES_DSN=production", "HOME=home"}
	want := []string{"PATH=bin", "HOME=home"}
	if got := cleanEnvironment(input); !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected filtered environment")
	}
}

func TestConnectionUsesOnlyLoopback(t *testing.T) {
	instance := cluster{port: 54321}
	parsed, err := url.Parse(instance.connection("mossward_test_backup", testRole, "secret"))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Host != "127.0.0.1:54321" || parsed.Query().Get("sslmode") != "disable" {
		t.Fatal("connection escaped disposable loopback scope")
	}
}

func TestPasswordsAreDistinctHex(t *testing.T) {
	first, err := randomPassword()
	if err != nil {
		t.Fatal(err)
	}
	second, err := randomPassword()
	if err != nil {
		t.Fatal(err)
	}
	if first == second || len(first) != passwordBytes*2 {
		t.Fatal("invalid random password")
	}
}

func TestMissingToolsFailBeforeProvisioning(t *testing.T) {
	if _, err := newCluster(t.TempDir()); err == nil {
		t.Fatal("missing tools accepted")
	}
}

func TestCleanupRetainsPotentiallyRunningCluster(t *testing.T) {
	directory := t.TempDir()
	data := filepath.Join(directory, "data")
	if err := os.Mkdir(data, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "postmaster.pid"), []byte("fake"), 0o600); err != nil {
		t.Fatal(err)
	}
	instance := cluster{directory: directory, tools: t.TempDir(), started: true}
	if err := instance.close(); err == nil {
		t.Fatal("uncertain stop accepted")
	}
	if _, err := os.Stat(data); err != nil {
		t.Fatal("potentially running data removed")
	}
}

func TestFailedStartupRemovesOwnedTemporaryFiles(t *testing.T) {
	directory := t.TempDir()
	instance := cluster{directory: directory, tools: t.TempDir()}
	if err := instance.start(context.Background(), 16); err == nil {
		t.Fatal("missing executable accepted")
	}
	if err := instance.close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(directory); !os.IsNotExist(err) {
		t.Fatal("temporary directory retained")
	}
}
