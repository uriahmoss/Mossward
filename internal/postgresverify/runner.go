package postgresverify

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
)

var testDatabases = map[string]string{
	"MOSSWARD_TEST_POSTGRES_DSN":          "mossward_test_repository",
	"MOSSWARD_TEST_POSTGRES_BACKUP_DSN":   "mossward_test_backup",
	"MOSSWARD_TEST_POSTGRES_RESTORE_DSN":  "mossward_test_restore",
	"MOSSWARD_TEST_POSTGRES_ROTATION_DSN": "mossward_test_rotation",
}

// Run executes the complete verification suite against an owned temporary cluster.
// Call from the repository root; tools must point to native PostgreSQL binaries.
func Run(ctx context.Context, tools string, expectedMajor int) (result error) {
	instance, err := newCluster(tools)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, instance.close()) }()
	if err := instance.start(ctx, expectedMajor); err != nil {
		return err
	}
	if err := instance.provision(ctx); err != nil {
		return err
	}
	environment := cleanEnvironment(os.Environ())
	for variable, database := range testDatabases {
		environment = append(environment, variable+"="+instance.connection(database, testRole, instance.testPassword))
	}
	environment = append(environment, "MOSSWARD_TEST_POSTGRES_TOOLS_DIR="+instance.tools)
	steps := [][]string{
		{"test", "-race", "-count=1", "-timeout=10m", "./..."},
		{"vet", "./..."},
		{"build", "-o", filepath.Join(instance.directory, "mossward"), "./cmd/mossward"},
		{"build", "-o", filepath.Join(instance.directory, "mossward-agent"), "./cmd/mossward-agent"},
	}
	for _, arguments := range steps {
		slog.Info("Running PostgreSQL verification step", "step", arguments[0])
		command := exec.CommandContext(ctx, "go", arguments...)
		command.Env, command.Stdout, command.Stderr = environment, os.Stdout, os.Stderr
		if err := command.Run(); err != nil {
			return fmt.Errorf("verification step %s failed: %w", arguments[0], err)
		}
	}
	return nil
}
