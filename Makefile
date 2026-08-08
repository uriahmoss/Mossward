.PHONY: build run test verify clean

GOCACHE ?= /private/tmp/mossward-go-cache

build:
	mkdir -p bin
	GOCACHE=$(GOCACHE) go build -o bin/mossward ./cmd/mossward
	GOCACHE=$(GOCACHE) go build -o bin/mossward-agent ./cmd/mossward-agent

run:
	GOCACHE=$(GOCACHE) go run ./cmd/mossward

test:
	GOCACHE=$(GOCACHE) go test -race ./...

verify:
	GOCACHE=$(GOCACHE) go test -race ./...
	GOCACHE=$(GOCACHE) go vet ./...
	$(MAKE) build

clean:
	go clean
