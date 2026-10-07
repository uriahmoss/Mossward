package serverbackup

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

type PostgreSQLOptions struct {
	URL      string
	ToolsDir string
}

func postgresToolPath(directory, name string) (string, error) {
	if directory != "" {
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		return filepath.Join(directory, name), nil
	}
	path, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("%s is required; install PostgreSQL client tools or supply --pg-tools-dir", name)
	}
	return path, nil
}

// Connection credentials never appear in command arguments or tool output.
// Remove inherited PG settings so a caller's environment cannot redirect tools.
func postgresToolEnvironment(connection, directory string) ([]string, error) {
	parsed, err := url.Parse(connection)
	if err != nil || (parsed.Scheme != "postgresql" && parsed.Scheme != "postgres") {
		return nil, errors.New("PostgreSQL maintenance requires a PostgreSQL connection URL")
	}
	parameters := map[string]string{}
	// Resolve supported libpq defaults into the private service file as well,
	// including TLS material. Explicit URL parameters always take precedence.
	for key, variable := range map[string]string{
		"host": "PGHOST", "port": "PGPORT", "user": "PGUSER", "dbname": "PGDATABASE", "password": "PGPASSWORD",
		"sslmode": "PGSSLMODE", "sslrootcert": "PGSSLROOTCERT", "sslcert": "PGSSLCERT", "sslkey": "PGSSLKEY", "passfile": "PGPASSFILE",
	} {
		if value := os.Getenv(variable); value != "" {
			parameters[key] = value
		}
	}
	for key, value := range map[string]string{"host": parsed.Hostname(), "port": parsed.Port(), "dbname": strings.TrimPrefix(parsed.Path, "/")} {
		if value != "" {
			parameters[key] = value
		}
	}
	for key, values := range parsed.Query() {
		if len(values) != 1 || key == "service" || key == "servicefile" || key == "passfile" {
			return nil, errors.New("unsupported PostgreSQL maintenance connection override")
		}
		parameters[key] = values[0]
	}
	if parsed.User != nil {
		if value, present := parsed.User.Password(); present {
			parameters["password"] = value
		}
		parameters["user"] = parsed.User.Username()
	}
	var service strings.Builder
	service.WriteString("[mossward]\n")
	for key, value := range parameters {
		if strings.ContainsAny(key, "\r\n=[]# ") || strings.ContainsAny(value, "\r\n") {
			return nil, errors.New("invalid PostgreSQL maintenance connection parameter")
		}
		if value != "" {
			fmt.Fprintf(&service, "%s=%s\n", key, value)
		}
	}
	servicefile := filepath.Join(directory, "pg-service.conf")
	if err := os.WriteFile(servicefile, []byte(service.String()), 0o600); err != nil {
		return nil, err
	}
	environment := []string{}
	for _, variable := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(variable), "PG") {
			environment = append(environment, variable)
		}
	}
	return append(environment, "PGSERVICEFILE="+servicefile), nil
}

func runPostgreSQLTool(ctx context.Context, options PostgreSQLOptions, directory, name string, arguments ...string) error {
	path, err := postgresToolPath(options.ToolsDir, name)
	if err != nil {
		return err
	}
	environment, err := postgresToolEnvironment(options.URL, directory)
	if err != nil {
		return err
	}
	command := exec.CommandContext(ctx, path, arguments...)
	command.Env = environment
	diagnostics := &postgresDiagnosticCounter{}
	command.Stderr = diagnostics
	slog.Info("PostgreSQL maintenance tool started", "tool", name)
	// Native stderr can contain credentials, row values, or SQL bodies. Withhold
	// it; operators can run their trusted tools separately for detailed diagnostics.
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("%s interrupted: %w", name, ctx.Err())
		}
		return fmt.Errorf("%s failed; check client/server compatibility, connectivity, permissions, and archive validity (tool details withheld)", name)
	}
	if diagnostics.bytes > 0 {
		slog.Warn("PostgreSQL maintenance tool reported diagnostics; review with trusted tools in a protected session", "tool", name)
	}
	return nil
}

type postgresDiagnosticCounter struct{ bytes int64 }

func (counter *postgresDiagnosticCounter) Write(data []byte) (int, error) {
	counter.bytes += int64(len(data))
	return len(data), nil
}
