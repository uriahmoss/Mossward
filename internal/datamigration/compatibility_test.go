package datamigration

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

func TestCopyColumnCompatibilityRejectsOmittedData(t *testing.T) {
	source := SourceReport{Tables: []TableSummary{{Name: "users", Columns: []string{"id", "email"}},
		{Name: "schema_migrations", Columns: []string{"version"}}}, Excluded: []string{"schema_migrations"}}
	for _, destination := range []map[string][]string{{}, {"users": {"id"}}} {
		if err := ValidateCopyColumns(source, destination); err == nil {
			t.Fatal("incomplete destination schema accepted")
		}
	}
	if err := ValidateCopyColumns(source, map[string][]string{"users": {"id", "email", "status"}}); err != nil {
		t.Fatal(err)
	}
}

func TestSourcePreflightRejectsBrokenReferences(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broken.db")
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	for _, statement := range []string{
		`CREATE TABLE schema_migrations(version INTEGER)`,
		`INSERT INTO schema_migrations VALUES(1)`,
		`CREATE TABLE parents(id INTEGER PRIMARY KEY)`,
		`CREATE TABLE children(parent_id INTEGER REFERENCES parents(id))`,
		`INSERT INTO children VALUES(99)`,
	} {
		if _, err := database.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := PreflightSQLiteSource(context.Background(), path); err == nil {
		t.Fatal("source with broken references accepted")
	}
}
