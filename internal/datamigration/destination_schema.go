package datamigration

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
)

type destinationColumn struct {
	Name, Type           string
	Nullable, HasDefault bool
}

func destinationColumns(ctx context.Context, tx *sql.Tx) (map[string][]destinationColumn, error) {
	rows, err := tx.QueryContext(ctx, `SELECT table_name,column_name,data_type,is_nullable='YES',column_default IS NOT NULL
	FROM information_schema.columns WHERE table_schema=current_schema() AND table_name<>'schema_migrations' ORDER BY table_name,ordinal_position`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := map[string][]destinationColumn{}
	for rows.Next() {
		var table string
		var column destinationColumn
		if err := rows.Scan(&table, &column.Name, &column.Type, &column.Nullable, &column.HasDefault); err != nil {
			return nil, err
		}
		result[table] = append(result[table], column)
	}
	return result, rows.Err()
}

func validateDestination(source SourceReport, destination map[string][]destinationColumn) error {
	source = mappedSourceColumns(source)
	names := map[string][]string{}
	for table, columns := range destination {
		for _, column := range columns {
			names[table] = append(names[table], column.Name)
		}
	}
	if err := ValidateCopyColumns(source, names); err != nil {
		return err
	}
	for table, columns := range destination {
		var sourceColumns []string
		for _, summary := range source.Tables {
			if summary.Name == table {
				sourceColumns = summary.Columns
				break
			}
		}
		if sourceColumns == nil {
			return fmt.Errorf("source is missing destination table %q", table)
		}
		for _, column := range columns {
			if !containsString(sourceColumns, column.Name) && !column.Nullable && !column.HasDefault {
				return fmt.Errorf("source is missing required field %s.%s", table, column.Name)
			}
		}
	}
	return nil
}

func migrationColumnName(table, column string) string {
	if table == "scanner_worker_dispatch_settings" && column == "id" {
		return "singleton"
	}
	return column
}

func mappedSourceColumns(source SourceReport) SourceReport {
	source.Tables = append([]TableSummary(nil), source.Tables...)
	for index, table := range source.Tables {
		columns := make([]string, len(table.Columns))
		for position, column := range table.Columns {
			columns[position] = migrationColumnName(table.Name, column)
		}
		source.Tables[index].Columns = columns
	}
	return source
}

func findColumn(columns []destinationColumn, name string) destinationColumn {
	for _, column := range columns {
		if column.Name == name {
			return column
		}
	}
	return destinationColumn{}
}

func destinationCopyOrder(ctx context.Context, tx *sql.Tx, tables []string) ([]string, error) {
	dependencies := map[string]map[string]bool{}
	for _, table := range tables {
		dependencies[table] = map[string]bool{}
	}
	rows, err := tx.QueryContext(ctx, `SELECT child.relname,parent.relname FROM pg_constraint fk
	JOIN pg_class child ON child.oid=fk.conrelid JOIN pg_class parent ON parent.oid=fk.confrelid
	WHERE fk.contype='f' AND child.relnamespace=current_schema()::regnamespace`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var child, parent string
		if err := rows.Scan(&child, &parent); err != nil {
			rows.Close()
			return nil, err
		}
		if child != parent {
			dependencies[child][parent] = true
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	order := []string{}
	for len(order) < len(tables) {
		ready := []string{}
		for table, required := range dependencies {
			if !containsString(order, table) && !hasPendingDependency(required, order) {
				ready = append(ready, table)
			}
		}
		if len(ready) == 0 {
			return nil, fmt.Errorf("destination has cyclic migration dependencies")
		}
		sort.Strings(ready)
		order = append(order, ready...)
	}
	return order, nil
}

func repairSequences(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, `SELECT table_name,column_name,pg_get_serial_sequence(quote_ident(table_schema)||'.'||quote_ident(table_name),column_name)
	FROM information_schema.columns WHERE table_schema=current_schema() AND (column_default LIKE 'nextval%' OR is_identity='YES')`)
	if err != nil {
		return err
	}
	type sequence struct{ table, column, name string }
	sequences := []sequence{}
	for rows.Next() {
		var item sequence
		if err := rows.Scan(&item.table, &item.column, &item.name); err != nil {
			rows.Close()
			return err
		}
		sequences = append(sequences, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, item := range sequences {
		query := "SELECT setval($1::regclass,COALESCE(MAX(" + quoteIdentifier(item.column) + "),1),COUNT(*)>0) FROM " + quoteIdentifier(item.table)
		if _, err := tx.ExecContext(ctx, query, item.name); err != nil {
			return fmt.Errorf("repair sequence for %s.%s", item.table, item.column)
		}
	}
	return nil
}
