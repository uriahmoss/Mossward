package datamigration

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"path/filepath"
	"sort"
	"strings"

	"mossward/internal/store"
)

type CopyReport struct {
	Tables   int   `json:"tables"`
	Rows     int64 `json:"rows"`
	Verified bool  `json:"verified"`
}

// CopySQLiteToPostgreSQL requires both services to be stopped. Schema creation,
// data insertion, sequence repair and verification commit as one transaction.
func CopySQLiteToPostgreSQL(ctx context.Context, path, dsn string) (CopyReport, error) {
	report := CopyReport{}
	source, err := PreflightSQLiteSource(ctx, path)
	if err != nil {
		return report, err
	}
	if source.SchemaVersion != store.SQLiteSchemaVersion() {
		return report, fmt.Errorf("migration requires SQLite schema %d; upgrade a backed-up source with the current Mossward build first", store.SQLiteSchemaVersion())
	}
	if _, err := PreflightPostgreSQLDestination(ctx, dsn); err != nil {
		return report, err
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return report, err
	}
	src, err := sql.Open("sqlite", readOnlySQLiteDSN(absolute))
	if err != nil {
		return report, err
	}
	defer src.Close()
	sourceTx, err := src.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return report, err
	}
	defer sourceTx.Rollback()
	var snapshotVersion int
	if err := sourceTx.QueryRowContext(ctx, `SELECT MAX(version) FROM schema_migrations`).Scan(&snapshotVersion); err != nil || snapshotVersion != source.SchemaVersion {
		return report, fmt.Errorf("migration source schema changed during preflight")
	}
	dst, err := sql.Open("pgx", dsn)
	if err != nil {
		return report, fmt.Errorf("open migration destination")
	}
	defer dst.Close()
	tx, err := dst.BeginTx(ctx, nil)
	if err != nil {
		return report, fmt.Errorf("begin migration destination transaction")
	}
	defer tx.Rollback()
	// Serialize cooperating migration utilities and recheck emptiness after locking.
	if err := store.LockPostgreSQLSchemaTransaction(ctx, tx); err != nil {
		return report, err
	}
	var occupied int
	if err := tx.QueryRowContext(ctx, `SELECT
		(SELECT COUNT(*) FROM pg_class WHERE relnamespace=current_schema()::regnamespace) +
		(SELECT COUNT(*) FROM pg_proc WHERE pronamespace=current_schema()::regnamespace) +
		(SELECT COUNT(*) FROM pg_type WHERE typnamespace=current_schema()::regnamespace)`).Scan(&occupied); err != nil {
		return report, err
	}
	if occupied != 0 {
		return report, fmt.Errorf("migration destination became occupied")
	}
	if err := store.InitializePostgreSQLTransaction(ctx, tx); err != nil {
		return report, err
	}
	tables, err := destinationColumns(ctx, tx)
	if err != nil {
		return report, err
	}
	if err := validateDestination(source, tables); err != nil {
		return report, err
	}
	order, err := destinationCopyOrder(ctx, tx, source.CopyOrder)
	if err != nil {
		return report, err
	}
	quoted := make([]string, 0, len(tables))
	for table := range tables {
		quoted = append(quoted, quoteIdentifier(table))
	}
	sort.Strings(quoted)
	// Remove schema defaults, including the generated installation identity; all
	// foreign-key-related tables are truncated together without disabling triggers.
	if _, err := tx.ExecContext(ctx, "TRUNCATE "+strings.Join(quoted, ",")); err != nil {
		return report, fmt.Errorf("clear destination defaults")
	}
	for _, table := range order {
		count, err := copyTable(ctx, sourceTx, tx, table, tables[table])
		if err != nil {
			return report, err
		}
		report.Tables++
		report.Rows += count
		slog.Info("Migration table verified", "table", table, "rows", count)
	}
	if err := repairSequences(ctx, tx); err != nil {
		return report, err
	}
	var organizations int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM installation_organization`).Scan(&organizations); err != nil || organizations != 1 {
		return report, fmt.Errorf("migration installation identity verification failed")
	}
	if err := tx.Commit(); err != nil {
		return report, fmt.Errorf("commit migration destination")
	}
	report.Verified = true
	slog.Info("Offline database migration committed", "tables", report.Tables, "rows", report.Rows)
	return report, nil
}

func quoteIdentifier(value string) string { return `"` + strings.ReplaceAll(value, `"`, `""`) + `"` }

func copyTable(ctx context.Context, src, dst *sql.Tx, table string, metadata []destinationColumn) (int64, error) {
	rows, err := src.QueryContext(ctx, "SELECT * FROM "+quoteIdentifier(table))
	if err != nil {
		return 0, fmt.Errorf("read source table %q", table)
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		return 0, err
	}
	quoted, placeholders := []string{}, []string{}
	for index, name := range columns {
		quoted = append(quoted, quoteIdentifier(name))
		placeholders = append(placeholders, fmt.Sprintf("$%d", index+1))
	}
	statement := "INSERT INTO " + quoteIdentifier(table) + " (" + strings.Join(quoted, ",") + ") VALUES (" + strings.Join(placeholders, ",") + ")"
	statement += " RETURNING " + strings.Join(quoted, ",")
	var count int64
	for rows.Next() {
		values, pointers := make([]any, len(columns)), make([]any, len(columns))
		for index := range values {
			pointers[index] = &values[index]
		}
		if err := rows.Scan(pointers...); err != nil {
			return 0, fmt.Errorf("read source row in %q", table)
		}
		for index, name := range columns {
			column := findColumn(metadata, name)
			values[index], err = ConvertValue(values[index], ColumnType(column.Type))
			if err != nil {
				return 0, fmt.Errorf("convert %s.%s: %w", table, name, err)
			}
		}
		returned, destinations := make([]any, len(columns)), make([]any, len(columns))
		for index := range returned {
			destinations[index] = &returned[index]
		}
		if err := dst.QueryRowContext(ctx, statement, values...).Scan(destinations...); err != nil {
			return 0, fmt.Errorf("insert migration row in %q (value details withheld)", table)
		}
		for index, name := range columns {
			if !equivalentValue(values[index], returned[index], ColumnType(findColumn(metadata, name).Type)) {
				return 0, fmt.Errorf("migration value verification failed for %s.%s", table, name)
			}
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	var destinationCount int64
	if err := dst.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+quoteIdentifier(table)).Scan(&destinationCount); err != nil || count != destinationCount {
		return 0, fmt.Errorf("migration row count verification failed for %q", table)
	}
	return count, nil
}
