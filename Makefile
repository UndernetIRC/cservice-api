BINDIR    := $(CURDIR)/bin
DISTDIR   := $(CURDIR)/dist
BINFILE   ?= cservice-api
TARGETS   ?= linux/amd64 darwin/amd64 freebsd/amd64

GOLANGCI_VERSION = 1.57.2
GORELEASER_VERSION = 1.21.2
SQLC_VERSION = 1.22.0

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

.PHONY: all mod build test integration-test test-run format migrateup migrateup1 migratedown migratedown1 sqlc mock build-cross docs clean
