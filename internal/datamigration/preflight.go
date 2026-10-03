package datamigration

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"

	_ "modernc.org/sqlite"
)

type SourceReport struct {
	Path          string         `json:"path"`
	SizeBytes     int64          `json:"size_bytes"`
	SchemaVersion int            `json:"schema_version"`
	TableCount    int            `json:"table_count"`
	TotalRows     int64          `json:"total_rows"`
	Tables        []TableSummary `json:"tables"`
}

type TableSummary struct {
	Name string `json:"name"`
	Rows int64  `json:"rows"`
}

func PreflightSQLiteSource(ctx context.Context, path string) (SourceReport, error) {
	info, err := os.Stat(path)
	if err != nil {
		return SourceReport{}, fmt.Errorf("inspect SQLite migration source: %w", err)
	}
	if !info.Mode().IsRegular() {
		return SourceReport{}, fmt.Errorf("SQLite migration source must be a regular file")
	}
	database, err := sql.Open("sqlite", readOnlySQLiteDSN(path))
	if err != nil {
		return SourceReport{}, fmt.Errorf("open SQLite migration source: %w", err)
	}
	defer database.Close()
	if err := database.PingContext(ctx); err != nil {
		return SourceReport{}, fmt.Errorf("connect to SQLite migration source: %w", err)
	}
	var integrity string
	if err := database.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&integrity); err != nil {
		return SourceReport{}, fmt.Errorf("check SQLite migration source integrity: %w", err)
	}
	if integrity != "ok" {
		return SourceReport{}, fmt.Errorf("SQLite migration source integrity check failed: %s", integrity)
	}
	report := SourceReport{Path: path, SizeBytes: info.Size()}
	if err := database.QueryRowContext(ctx, `SELECT COALESCE(MAX(version),0) FROM schema_migrations`).Scan(&report.SchemaVersion); err != nil {
		return SourceReport{}, fmt.Errorf("read SQLite migration source schema version: %w", err)
	}
	tableNames, err := sqliteTableNames(ctx, database)
	if err != nil {
		return SourceReport{}, err
	}
	for _, name := range tableNames {
		var rows int64
		query := `SELECT COUNT(*) FROM "` + strings.ReplaceAll(name, `"`, `""`) + `"`
		if err := database.QueryRowContext(ctx, query).Scan(&rows); err != nil {
			return SourceReport{}, fmt.Errorf("count SQLite migration source table %q: %w", name, err)
		}
		report.Tables = append(report.Tables, TableSummary{Name: name, Rows: rows})
		report.TotalRows += rows
	}
	report.TableCount = len(report.Tables)
	return report, nil
}

func sqliteTableNames(ctx context.Context, database *sql.DB) ([]string, error) {
	rows, err := database.QueryContext(ctx, `SELECT name FROM sqlite_master
		WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list SQLite migration source tables: %w", err)
	}
	defer rows.Close()
	names := []string{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("read SQLite migration source table: %w", err)
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Strings(names)
	return names, nil
}

func readOnlySQLiteDSN(path string) string {
	value := &url.URL{Scheme: "file", Path: path}
	query := value.Query()
	query.Set("mode", "ro")
	value.RawQuery = query.Encode()
	return value.String()
}
