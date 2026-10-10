package datamigration

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
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
	CopyOrder     []string       `json:"copy_order"`
	Excluded      []string       `json:"excluded"`
}

type TableSummary struct {
	Name    string   `json:"name"`
	Rows    int64    `json:"rows"`
	Columns []string `json:"columns"`
}

func PreflightSQLiteSource(ctx context.Context, path string) (SourceReport, error) {
	info, err := os.Stat(path)
	if err != nil {
		return SourceReport{}, fmt.Errorf("inspect SQLite migration source: %w", err)
	}
	if !info.Mode().IsRegular() {
		return SourceReport{}, fmt.Errorf("SQLite migration source must be a regular file")
	}
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return SourceReport{}, fmt.Errorf("resolve SQLite migration source path: %w", err)
	}
	database, err := sql.Open("sqlite", readOnlySQLiteDSN(absolutePath))
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
	if err := checkSourceForeignKeys(ctx, database); err != nil {
		return SourceReport{}, err
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
		columns, err := sourceColumns(ctx, database, name)
		if err != nil {
			return SourceReport{}, err
		}
		report.Tables = append(report.Tables, TableSummary{Name: name, Rows: rows, Columns: columns})
		report.TotalRows += rows
	}
	report.TableCount = len(report.Tables)
	report.Excluded = []string{"schema_migrations"}
	report.CopyOrder, err = sqliteCopyOrder(ctx, database, tableNames, report.Excluded)
	if err != nil {
		return SourceReport{}, err
	}
	return report, nil
}

func sqliteCopyOrder(ctx context.Context, database *sql.DB, tableNames, excluded []string) ([]string, error) {
	excludedSet := make(map[string]bool, len(excluded))
	for _, name := range excluded {
		excludedSet[name] = true
	}
	known := make(map[string]bool, len(tableNames))
	dependencies := map[string]map[string]bool{}
	for _, name := range tableNames {
		known[name] = true
		if !excludedSet[name] {
			dependencies[name] = map[string]bool{}
		}
	}
	for name := range dependencies {
		foreignKeys, err := sqliteForeignKeyTables(ctx, database, name)
		if err != nil {
			return nil, err
		}
		for _, dependency := range foreignKeys {
			if dependency == name {
				continue
			}
			if excludedSet[dependency] {
				continue
			}
			if !known[dependency] {
				return nil, fmt.Errorf("SQLite migration source table %q references missing table %q", name, dependency)
			}
			dependencies[name][dependency] = true
		}
	}
	order := make([]string, 0, len(dependencies))
	for len(order) < len(dependencies) {
		ready := []string{}
		for name, required := range dependencies {
			if containsString(order, name) || hasPendingDependency(required, order) {
				continue
			}
			ready = append(ready, name)
		}
		if len(ready) == 0 {
			return nil, fmt.Errorf("SQLite migration source contains cyclic table dependencies")
		}
		sort.Strings(ready)
		order = append(order, ready...)
	}
	return order, nil
}

func sqliteForeignKeyTables(ctx context.Context, database *sql.DB, table string) ([]string, error) {
	query := `PRAGMA foreign_key_list("` + strings.ReplaceAll(table, `"`, `""`) + `")`
	rows, err := database.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("read SQLite migration source dependencies for %q: %w", table, err)
	}
	defer rows.Close()
	dependencies := []string{}
	for rows.Next() {
		var id, sequence int
		var dependency, from, to, onUpdate, onDelete, match string
		if err := rows.Scan(&id, &sequence, &dependency, &from, &to, &onUpdate, &onDelete, &match); err != nil {
			return nil, fmt.Errorf("scan SQLite migration source dependency for %q: %w", table, err)
		}
		dependencies = append(dependencies, dependency)
	}
	return dependencies, rows.Err()
}

func hasPendingDependency(dependencies map[string]bool, ordered []string) bool {
	for dependency := range dependencies {
		if !containsString(ordered, dependency) {
			return true
		}
	}
	return false
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
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
	slashPath := filepath.ToSlash(path)
	if filepath.VolumeName(path) != "" && !strings.HasPrefix(slashPath, "/") {
		slashPath = "/" + slashPath
	}
	value := &url.URL{Scheme: "file", Path: slashPath}
	query := value.Query()
	query.Set("mode", "ro")
	value.RawQuery = query.Encode()
	return value.String()
}
