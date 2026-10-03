package datamigration

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"

	_ "github.com/jackc/pgx/v5/stdlib"
)

const minimumPostgreSQLMajorVersion = 14

type DestinationReport struct {
	ServerMajorVersion int    `json:"server_major_version"`
	Schema             string `json:"schema"`
	RelationCount      int    `json:"relation_count"`
	Empty              bool   `json:"empty"`
}

func PreflightPostgreSQLDestination(ctx context.Context, dsn string) (DestinationReport, error) {
	if dsn == "" {
		return DestinationReport{}, fmt.Errorf("PostgreSQL migration destination URL is required")
	}
	database, err := sql.Open("pgx", dsn)
	if err != nil {
		return DestinationReport{}, fmt.Errorf("open PostgreSQL migration destination: %w", err)
	}
	defer database.Close()
	if err := database.PingContext(ctx); err != nil {
		return DestinationReport{}, fmt.Errorf("connect to PostgreSQL migration destination: %w", err)
	}
	var versionText string
	report := DestinationReport{}
	if err := database.QueryRowContext(ctx, `SHOW server_version_num`).Scan(&versionText); err != nil {
		return DestinationReport{}, fmt.Errorf("read PostgreSQL migration destination version: %w", err)
	}
	version, err := strconv.Atoi(versionText)
	if err != nil {
		return DestinationReport{}, fmt.Errorf("parse PostgreSQL migration destination version: %w", err)
	}
	report.ServerMajorVersion = version / 10000
	if report.ServerMajorVersion < minimumPostgreSQLMajorVersion {
		return DestinationReport{}, fmt.Errorf("PostgreSQL %d or newer is required", minimumPostgreSQLMajorVersion)
	}
	if err := database.QueryRowContext(ctx, `SELECT current_schema()`).Scan(&report.Schema); err != nil {
		return DestinationReport{}, fmt.Errorf("read PostgreSQL migration destination schema: %w", err)
	}
	if report.Schema == "" {
		return DestinationReport{}, fmt.Errorf("PostgreSQL migration destination has no current schema")
	}
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM pg_catalog.pg_class c
		JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
		WHERE n.nspname=current_schema() AND c.relkind IN ('r','p','v','m','S','f')`).Scan(&report.RelationCount); err != nil {
		return DestinationReport{}, fmt.Errorf("inspect PostgreSQL migration destination schema: %w", err)
	}
	report.Empty = report.RelationCount == 0
	if !report.Empty {
		return report, fmt.Errorf("PostgreSQL migration destination schema %q is not empty (%d relations)",
			report.Schema, report.RelationCount)
	}
	return report, nil
}
