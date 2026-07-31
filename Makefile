.PHONY: build run test verify clean

GOCACHE ?= /private/tmp/mossward-go-cache
GOPATH ?= /private/tmp/mossward-gopath

build:
	mkdir -p bin
	GOCACHE=$(GOCACHE) GOPATH=$(GOPATH) go build -o bin/mossward ./cmd/mossward

run:
	GOCACHE=$(GOCACHE) GOPATH=$(GOPATH) go run ./cmd/mossward

test:
	GOCACHE=$(GOCACHE) GOPATH=$(GOPATH) go test -race ./...

verify:
	GOCACHE=$(GOCACHE) GOPATH=$(GOPATH) go test -race ./...
	GOCACHE=$(GOCACHE) GOPATH=$(GOPATH) go vet ./...
	$(MAKE) build

clean:
	go clean
