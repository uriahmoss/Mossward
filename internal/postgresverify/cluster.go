// Package postgresverify provisions disposable local databases for verification.
// It cannot connect to an existing server or accept an operator-supplied DSN.
package postgresverify

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

const (
	adminRole      = "mossward_ci_admin"
	testRole       = "mossward_test"
	minimumMajor   = 14
	passwordBytes  = 32
	cleanupTimeout = 30 * time.Second
)

var versionPattern = regexp.MustCompile(`PostgreSQL\)\s+(\d+)\.`)

type cluster struct {
	directory, tools, password, testPassword string
	port                                     int
	started                                  bool
}

func newCluster(tools string) (*cluster, error) {
	if tools == "" {
		return nil, errors.New("a PostgreSQL tools directory is required")
	}
	absolute, err := filepath.Abs(tools)
	if err != nil {
		return nil, err
	}
	for _, name := range []string{"postgres", "initdb", "pg_ctl", "pg_dump", "pg_restore"} {
		info, err := os.Stat(toolPath(absolute, name))
		if err != nil || !info.Mode().IsRegular() {
			return nil, fmt.Errorf("PostgreSQL tool %s is unavailable", name)
		}
	}
	password, err := randomPassword()
	if err != nil {
		return nil, err
	}
	testPassword, err := randomPassword()
	if err != nil {
		return nil, err
	}
	port, err := availablePort()
	if err != nil {
		return nil, err
	}
	directory, err := os.MkdirTemp("", "mossward-postgres-verify-")
	if err != nil {
		return nil, err
	}
	return &cluster{directory: directory, tools: absolute, password: password, testPassword: testPassword, port: port}, nil
}

func randomPassword() (string, error) {
	bytes := make([]byte, passwordBytes)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func availablePort() (int, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

func toolPath(directory, name string) string {
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(directory, name)
}

func (cluster *cluster) command(ctx context.Context, name string, args ...string) error {
	command := exec.CommandContext(ctx, toolPath(cluster.tools, name), args...)
	command.Env = cleanEnvironment(os.Environ())
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("PostgreSQL verification tool %s interrupted: %w", name, ctx.Err())
		}
		return fmt.Errorf("PostgreSQL verification tool %s failed (diagnostics withheld)", name)
	}
	return nil
}

func (cluster *cluster) start(ctx context.Context, expectedMajor int) error {
	command := exec.CommandContext(ctx, toolPath(cluster.tools, "postgres"), "--version")
	command.Env = cleanEnvironment(os.Environ())
	version, err := command.Output()
	if err != nil {
		return errors.New("read PostgreSQL tool version failed")
	}
	major, err := parseMajor(string(version), expectedMajor)
	if err != nil {
		return err
	}
	slog.Info("Starting isolated PostgreSQL verification", "major", major, "os", runtime.GOOS)
	passwordFile := filepath.Join(cluster.directory, "admin.password")
	if err := os.WriteFile(passwordFile, []byte(cluster.password+"\n"), 0o600); err != nil {
		return err
	}
	data := filepath.Join(cluster.directory, "data")
	if err := cluster.command(ctx, "initdb", "--pgdata="+data, "--username="+adminRole, "--pwfile="+passwordFile, "--auth-host=scram-sha-256", "--auth-local=scram-sha-256", "--encoding=UTF8", "--no-locale"); err != nil {
		return err
	}
	configuration := fmt.Sprintf("\nlisten_addresses = '127.0.0.1'\nport = %d\nunix_socket_directories = ''\n", cluster.port)
	file, err := os.OpenFile(filepath.Join(data, "postgresql.conf"), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := file.WriteString(configuration)
	if err := errors.Join(writeErr, file.Close()); err != nil {
		return err
	}
	// Even a timed-out start may have launched the server. Always attempt a stop.
	cluster.started = true
	return cluster.command(ctx, "pg_ctl", "--pgdata="+data, "--log="+filepath.Join(cluster.directory, "server.log"), "--wait", "--timeout=60", "start")
}

func parseMajor(version string, expected int) (int, error) {
	match := versionPattern.FindStringSubmatch(version)
	if len(match) != 2 {
		return 0, errors.New("unrecognized PostgreSQL tool version")
	}
	major, err := strconv.Atoi(match[1])
	if err != nil || major < minimumMajor || (expected != 0 && major != expected) {
		return 0, fmt.Errorf("PostgreSQL major does not match the required supported version (actual %d, expected %d)", major, expected)
	}
	return major, nil
}

func (cluster *cluster) connection(database, role, password string) string {
	connection := url.URL{Scheme: "postgresql", Host: net.JoinHostPort("127.0.0.1", strconv.Itoa(cluster.port)), Path: "/" + database, User: url.UserPassword(role, password)}
	query := url.Values{"sslmode": {"disable"}, "connect_timeout": {"5"}}
	connection.RawQuery = query.Encode()
	return connection.String()
}

func (cluster *cluster) provision(ctx context.Context) error {
	database, err := sql.Open("pgx", cluster.connection("postgres", adminRole, cluster.password))
	if err != nil {
		return errors.New("open isolated PostgreSQL administrator connection failed")
	}
	defer database.Close()
	// Passwords are generated hex strings, not operator input; utility statements
	// do not accept SQL value parameters. Never log these statements or DSNs.
	if _, err := database.ExecContext(ctx, "CREATE ROLE "+testRole+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD '"+cluster.testPassword+"'"); err != nil {
		return errors.New("create least-privilege PostgreSQL test role failed")
	}
	for _, name := range testDatabases {
		if _, err := database.ExecContext(ctx, "CREATE DATABASE "+name+" OWNER "+testRole); err != nil {
			return errors.New("create isolated PostgreSQL test database failed")
		}
	}
	return nil
}

func (cluster *cluster) close() error {
	ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	if cluster.started {
		data := filepath.Join(cluster.directory, "data")
		if err := cluster.command(ctx, "pg_ctl", "--pgdata="+data, "--wait", "--timeout=20", "--mode=fast", "stop"); err != nil {
			// Never remove a data directory while its server might still be running.
			if _, pidErr := os.Stat(filepath.Join(data, "postmaster.pid")); !os.IsNotExist(pidErr) {
				return fmt.Errorf("verification cluster could not be stopped; retain %s for manual cleanup", cluster.directory)
			}
		}
	}
	if err := os.RemoveAll(cluster.directory); err != nil {
		return err
	}
	slog.Info("Isolated PostgreSQL verification cluster removed")
	return nil
}

func cleanEnvironment(environment []string) []string {
	cleaned := []string{}
	for _, variable := range environment {
		upper := strings.ToUpper(variable)
		if strings.HasPrefix(upper, "PG") || strings.HasPrefix(upper, "MOSSWARD_") {
			continue
		}
		cleaned = append(cleaned, variable)
	}
	return cleaned
}
