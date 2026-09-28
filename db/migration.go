// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

// Package db defines the database types and functions.
package db

import (
	"embed"
	"fmt"
	"io/fs"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/labstack/gommon/log"
	"github.com/undernetirc/cservice-api/internal/config"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// Migrator is the subset of *migrate.Migrate that MigrationHandler uses.
// Extracted as an interface so tests can substitute a fake without needing
// a live database connection.
type Migrator interface {
	Steps(n int) error
	Version() (version uint, dirty bool, err error)
	Up() error
	Force(version int) error
}

// MigrationHandler wraps a Migrator and layers on the project-specific
// migration workflows (single-step, apply-all, force-version).
type MigrationHandler struct {
	m Migrator
}

// NewMigrationHandler builds a MigrationHandler backed by a real
// *migrate.Migrate reading the embedded migrations and the DB URI from
// config.
func NewMigrationHandler() (*MigrationHandler, error) {
	d, err := iofs.New(&migrationFS, "migrations")
	if err != nil {
		return nil, err
	}
	m, err := migrate.NewWithSourceInstance("iofs", d, config.GetDbURI())
	if err != nil {
		return nil, err
	}

	return &MigrationHandler{m: m}, nil
}

// NewMigrationHandlerWith wraps an arbitrary Migrator (typically a test
// double) so callers can exercise MigrationHandler without touching a real
// database.
func NewMigrationHandlerWith(m Migrator) *MigrationHandler {
	return &MigrationHandler{m: m}
}

// MigrationStep applies `step` migrations (step > 0 = up, step < 0 = down)
// and returns the resulting schema version on success. Callers own the
// log/exit decision so the library can be tested without process termination.
func (h *MigrationHandler) MigrationStep(step int) (uint, error) {
	if err := h.m.Steps(step); err != nil {
		direction := "up"
		if step < 0 {
			direction = "down"
		}
		return 0, fmt.Errorf("failed to run migration %s: %w", direction, err)
	}
	ver, _, err := h.m.Version()
	if err != nil {
		return 0, err
	}
	return ver, nil
}

// RunMigrations applies all pending migrations. golang-migrate reports a
// no-op run via a "no change" error, which is treated as success here.
func (h *MigrationHandler) RunMigrations() error {
	log.Info("Running database migrations")
	if err := h.m.Up(); err != nil {
		if strings.Contains(err.Error(), "no change") {
			log.Info("Database migration: NO CHANGE")
			return nil
		}
		return err
	}
	log.Info("Database migration: SUCCESS")
	return nil
}

// ForceVersion sets the schema version, bypassing dirty-state checks.
// Callers own the log/exit decision.
func (h *MigrationHandler) ForceVersion(version int) error {
	return h.m.Force(version)
}

// ListMigrations returns a list of all migration files.
func ListMigrations() ([]string, error) {
	var files []string
	if err := fs.WalkDir(&migrationFS, ".", func(path string, d fs.DirEntry, _ error) error {
		if d.IsDir() {
			return nil
		}
		files = append(files, path)
		return nil
	}); err != nil {
		return nil, err
	}
	return files, nil
}

// ViewMigration returns the raw contents of a single migration file.
func ViewMigration(file string) []byte {
	f, _ := migrationFS.ReadFile(file)
	return f
}
