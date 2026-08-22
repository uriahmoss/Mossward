package store

import "testing"

func TestBindQueryUsesPostgreSQLPlaceholdersWithoutChangingQuotedText(t *testing.T) {
	query := `SELECT "?",'it''s ?' FROM scope_policies WHERE id=? AND name=?`
	want := `SELECT "?",'it''s ?' FROM scope_policies WHERE id=$1 AND name=$2`
	if got := bindQuery(dialectPostgreSQL, query); got != want {
		t.Fatalf("PostgreSQL query = %q, want %q", got, want)
	}
	if got := bindQuery(dialectSQLite, query); got != query {
		t.Fatalf("SQLite query changed to %q", got)
	}
}
