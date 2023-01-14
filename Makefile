BINDIR    := $(CURDIR)/bin
DISTDIR   := $(CURDIR)/dist
BINFILE   ?= cservice-api
TARGETS   ?= linux/amd64 darwin/amd64 freebsd/amd64

DB_URL    = postgres://cservice:cservice@localhost:5432/cservice?sslmode=disable
GOPATH    ?= $(shell go env GOPATH)
GOX       = $(GOPATH)/bin/gox
GOIMPORTS = $(GOPATH)/bin/goimports
AIR       = $(GOPATH)/bin/air
SWAG      = $(GOPATH)/bin/swag
MIGRATE   = $(GOPATH)/bin/migrate
SQLC      = $(GOPATH)/bin/sqlc
MOCKERY   = $(GOPATH)/bin/mockery

PKG       := ./...
TESTS     := .
TESTFLAGS := -race -v
LDFLAGS   :=
GOFLAGS   := -mod=vendor
SRC       := $(shell find . -type f -name '*.go' -print)

SHELL      = /bin/bash

all: build

mod:
	go mod download
	go mod tidy
	go mod vendor

build: mod $(BINDIR)/$(BINFILE)

$(BINDIR)/$(BINFILE): $(SRC)
	go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $@

test: TEST_TYPE = unit
test: test-run

integration-test: TEST_TYPE = integration
integration-test: TESTFLAGS += -tags integration
integration-test: PKG = ./integration
integration-test: test-run

test-run:
	@echo
	@echo "--- Running $(TEST_TYPE) tests"
	go test -run $(TESTS) $(PKG) $(TESTFLAGS)

format: $(GOIMPORTS)
	go list -f '{{.Dir}}' ./... | grep -v 'vendor' | grep -v "$(CURDIR)" | xargs $(GOIMPORTS) -w *.go

# Dependencies that should not be added to the go.mod file goes here.
$(GOX):
	go install github.com/mitchellh/gox@latest

$(GOIMPORTS):
	go install golang.org/x/tools/cmd/goimports@latest

$(AIR):
	go install github.com/cosmtrek/air@latest

$(SWAG):
	go install github.com/swaggo/swag/cmd/swag@latest

$(MIGRATE):
	go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest

$(SQLC):
	go install github.com/kyleconroy/sqlc/cmd/sqlc@1b624dbc044fd9b50038407477062a51360b9904

$(MOCKERY):
	go install github.com/vektra/mockery/v2@latest
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

build-cross: LDFLAGS += -extldflags "-static"
build-cross: $(GOX)
	GOFLAGS=$(GOFLAGS) CGO_ENABLED=1 $(GOX) -parallel=3 -output="$(DISTDIR)/{{.OS}}-{{.Arch}}/$(BINFILE)" -osarch='$(TARGETS)' -tags '$(TAGS)' -ldflags '$(LDFLAGS)' $(PKG)

watch: $(AIR)
	$(AIR)

docs: $(SWAG)
	$(SWAG) init

clean:
	@rm -rf "$(BINDIR)" "$(DISTDIR)"

.PHONY: all mod build test integration-test test-run format migrateup migrateup1 migratedown migratedown1 sqlc mock build-cross docs clean
