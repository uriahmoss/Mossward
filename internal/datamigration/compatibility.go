package datamigration

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

func checkSourceForeignKeys(ctx context.Context, database *sql.DB) error {
	rows, err := database.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		return fmt.Errorf("check SQLite migration source references: %w", err)
	}
	defer rows.Close()
	if rows.Next() {
		return fmt.Errorf("SQLite migration source contains foreign-key violations")
	}
	return rows.Err()
}

func sourceColumns(ctx context.Context, database *sql.DB, table string) ([]string, error) {
	rows, err := database.QueryContext(ctx, `SELECT * FROM "`+strings.ReplaceAll(table, `"`, `""`)+`" LIMIT 0`)
	if err != nil {
		return nil, fmt.Errorf("inspect SQLite migration source columns for %q: %w", table, err)
	}
	defer rows.Close()
	return rows.Columns()
}

// ValidateCopyColumns checks that every planned source field has a destination.
// Destination-only fields and value conversion require separate validation.
func ValidateCopyColumns(source SourceReport, destination map[string][]string) error {
	for _, table := range source.Tables {
		if containsString(source.Excluded, table.Name) {
			continue
		}
		columns, exists := destination[table.Name]
		if !exists {
			return fmt.Errorf("migration destination is missing table %q", table.Name)
		}
		for _, column := range table.Columns {
			if !containsString(columns, column) {
				return fmt.Errorf("migration destination table %q is missing column %q", table.Name, column)
			}
		}
	}
	return nil
}
