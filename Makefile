.PHONY: build run test test-postgres verify clean

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
	GOCACHE=$(GOCACHE) go test -race ./internal/store -run '^TestPostgreSQL(Migrations|Startup|ScanAndAsset|LocalAuth|Audit|SessionAndInvitation|IdentityAdministration|WebAuthn|OIDC|ScopeAndPolicy|EndpointIdentity|EndpointInventory|EndpointIntegrity|EndpointNetwork|Relay|Maintenance|EndpointCoverage|WorkerIdentity|WorkerJobLease|WorkerEvidence|WorkerReassignment|WorkerJobDeadLetter|FindingWorkflow|Notification|AgentUpdate|AgentModule|AssetMerge|AssetLifecycle|IdentityCiphertext|CVEFeed)' -count=1
	GOCACHE=$(GOCACHE) go test -race ./internal/datamigration -run '^TestPostgreSQL' -count=1

verify:
	GOCACHE=$(GOCACHE) go test -race ./...
	GOCACHE=$(GOCACHE) go vet ./...
	$(MAKE) build

clean:
	go clean
