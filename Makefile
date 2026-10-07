.PHONY: build run test test-postgres test-postgres-recovery verify clean

GOCACHE ?= /private/tmp/mossward-go-cache

build:
	mkdir -p bin
	GOCACHE=$(GOCACHE) go build -o bin/mossward ./cmd/mossward
	GOCACHE=$(GOCACHE) go build -o bin/mossward-agent ./cmd/mossward-agent

run:
	GOCACHE=$(GOCACHE) go run ./cmd/mossward

test:
	GOCACHE=$(GOCACHE) go test -race ./...

test-postgres:
	@test -n "$${MOSSWARD_TEST_POSTGRES_DSN:-}" || { echo 'MOSSWARD_TEST_POSTGRES_DSN is required for live PostgreSQL verification'; exit 1; }
	GOCACHE=$(GOCACHE) go test -race ./internal/store -run '^TestPostgreSQL' -count=1
	GOCACHE=$(GOCACHE) go test -race ./internal/datamigration -run '^TestPostgreSQL' -count=1

test-postgres-recovery:
	@test -n "$${MOSSWARD_TEST_POSTGRES_BACKUP_DSN:-}" -a -n "$${MOSSWARD_TEST_POSTGRES_RESTORE_DSN:-}" -a -n "$${MOSSWARD_TEST_POSTGRES_ROTATION_DSN:-}" || { echo 'Dedicated BACKUP, RESTORE, and ROTATION PostgreSQL test DSNs are required'; exit 1; }
	GOCACHE=$(GOCACHE) go test -race ./internal/serverbackup ./cmd/mossward -run '^TestPostgreSQL' -count=1

verify:
	GOCACHE=$(GOCACHE) go test -race ./...
	GOCACHE=$(GOCACHE) go vet ./...
	$(MAKE) build

clean:
	go clean
