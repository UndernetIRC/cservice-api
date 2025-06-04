BINDIR    := $(CURDIR)/bin
DISTDIR   := $(CURDIR)/dist
BINFILE   ?= cservice-api
TARGETS   ?= linux/amd64 darwin/amd64 freebsd/amd64

GOLANGCI_VERSION = 2.1.1
GORELEASER_VERSION = 1.21.2
SQLC_VERSION = 1.29.0

DB_URL     ?= postgres://cservice:cservice@localhost:5432/cservice?sslmode=disable
GOPATH     ?= $(shell go env GOPATH)
GOX        = $(GOPATH)/bin/gox
AIR        = $(GOPATH)/bin/air
SWAG       = $(GOPATH)/bin/swag
MIGRATE    = $(GOPATH)/bin/migrate
SQLC       = $(GOPATH)/bin/sqlc
MOCKERY    = $(GOPATH)/bin/mockery
GORELEASER = $(GOPATH)/bin/goreleaser

PKG       := ./...
TESTS     := .
TESTFLAGS := -v
LDFLAGS   :=
GOFLAGS   :=
SRC       := $(shell find . -type f -name '*.go' -print)

SHELL      = /bin/bash

all: build

mod:
	go mod download
	go mod tidy

build: $(BINDIR)/$(BINFILE)

$(BINDIR)/$(BINFILE): $(SRC)
	go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $@ ./cmd/cservice-api/main.go

test: TEST_TYPE = unit
test: TESTFLAGS += -coverprofile=coverage.out -covermode=atomic
test: test-run

integration-test: TEST_TYPE = integration
integration-test: TESTFLAGS += -tags integration
integration-test: PKG = ./integration
integration-test: test-run

# New comprehensive testing targets
test-all: test integration-test benchmark-test security-test

# Security-focused tests
security-test: TEST_TYPE = security
security-test: TESTFLAGS += -v -run TestSecurity
security-test: test-run

# Performance benchmark tests
benchmark-test: TEST_TYPE = benchmark
benchmark-test: PKG = ./benchmarks
benchmark-test: TESTFLAGS += -bench=. -benchmem -cpuprofile=cpu.prof -memprofile=mem.prof
benchmark-test: test-run

# Coverage report generation
coverage-report: test
	@echo "--- Generating coverage report"
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Coverage with threshold check (95% target)
coverage-check: test
	@echo "--- Checking coverage threshold"
	@go tool cover -func=coverage.out | tail -1 | awk '{print "Total coverage: " $$3}' | tee coverage.txt
	@COVERAGE=$$(go tool cover -func=coverage.out | tail -1 | awk '{print $$3}' | sed 's/%//'); \
	if [ $${COVERAGE%.*} -lt 95 ]; then \
		echo "ERROR: Coverage $${COVERAGE}% is below 95% threshold"; \
		exit 1; \
	else \
		echo "SUCCESS: Coverage $${COVERAGE}% meets 95% threshold"; \
	fi

# Race condition detection
test-race: TEST_TYPE = race
test-race: TESTFLAGS += -race -coverprofile=coverage-race.out -covermode=atomic
test-race: test-run

# Stress testing
test-stress: TEST_TYPE = stress
test-stress: TESTFLAGS += -count=100 -parallel=10
test-stress: test-run

# Short test run (skip long-running tests)
test-short: TEST_TYPE = short
test-short: TESTFLAGS += -short -coverprofile=coverage-short.out -covermode=atomic
test-short: test-run

# Verbose test output
test-verbose: TEST_TYPE = verbose
test-verbose: TESTFLAGS += -v -coverprofile=coverage-verbose.out -covermode=atomic
test-verbose: test-run

# Test with timeout
test-timeout: TEST_TYPE = timeout
test-timeout: TESTFLAGS += -timeout=30s -coverprofile=coverage-timeout.out -covermode=atomic
test-timeout: test-run

# Load testing (requires special setup)
load-test:
	@echo "--- Running load tests"
	@if command -v hey >/dev/null 2>&1; then \
		echo "Using hey for load testing"; \
		hey -n 1000 -c 10 -H "Authorization: Bearer test-token" http://localhost:8080/api/v1/health; \
	else \
		echo "Load testing tool 'hey' not found. Install with: go install github.com/rakyll/hey@latest"; \
		echo "Falling back to basic load test"; \
		go test -v ./benchmarks -run=^$$ -bench=BenchmarkLoad; \
	fi

test-run:
	@echo
	@echo "--- Running $(TEST_TYPE) tests"
	go test -run $(TESTS) $(PKG) $(TESTFLAGS)

lint:
	@echo "--- Linting"
	@docker run --rm -v $(CURDIR):/app -w /app golangci/golangci-lint:v$(GOLANGCI_VERSION) golangci-lint run -v

lint-fix:
	@echo "--- Linting and fixing"
	@docker run --rm -v $(CURDIR):/app -w /app golangci/golangci-lint:v$(GOLANGCI_VERSION) golangci-lint run -v --fix


# Dependencies that should not be added to the go.mod file goes here.
$(GOX):
	go install github.com/mitchellh/gox@latest

$(AIR):
	go install github.com/air-verse/air@latest

$(SWAG):
	go install github.com/swaggo/swag/cmd/swag@latest

$(MIGRATE):
	go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest

$(SQLC):
	go install github.com/sqlc-dev/sqlc/cmd/sqlc@v$(SQLC_VERSION)

$(MOCKERY):
	go install github.com/vektra/mockery/v2@latest

$(GORELEASER):
	go install github.com/goreleaser/goreleaser@v$(GORELEASER_VERSION)
# END external dependencies

migrateup: $(MIGRATE)
	$(MIGRATE) -path db/migrations -database "$(DB_URL)" up

migrateup1: $(MIGRATE)
	$(MIGRATE) -path db/migrations -database "$(DB_URL)" up 1

migratedown: $(MIGRATE)
	$(MIGRATE) -path db/migrations -database "$(DB_URL)" down

migratedown1: $(MIGRATE)
	$(MIGRATE) -path db/migrations -database "$(DB_URL)" down 1

generate-sqlc: $(SQLC)
	$(SQLC) generate

generate-mocks: $(MOCKERY)
	$(MOCKERY) --output db/mocks --dir models/ --all

build-cross: $(GORELEASER)
	$(GORELEASER) build --snapshot --rm-dist

watch: $(AIR)
	$(AIR)

docs: $(SWAG)
	$(SWAG) init -d cmd/cservice-api,./ -o internal/docs

clean:
	@rm -rf "$(BINDIR)" "$(DISTDIR)"

.PHONY: all mod build test integration-test test-all security-test benchmark-test coverage-report coverage-check test-race test-stress test-short test-verbose test-timeout load-test test-run format migrateup migrateup1 migratedown migratedown1 sqlc mock build-cross docs clean
