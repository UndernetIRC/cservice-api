// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

// Package db defines the database types and functions.
package db

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/labstack/gommon/log"
	"github.com/undernetirc/cservice-api/internal/config"
	"github.com/undernetirc/cservice-api/internal/globals"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

type MigrationHandler struct {
	*migrate.Migrate
}

func NewMigrationHandler() (*MigrationHandler, error) {
	d, err := iofs.New(&migrationFS, "migrations")
	if err != nil {
		return nil, err
	}
	m, err := migrate.NewWithSourceInstance("iofs", d, config.GetDbURI())
	if err != nil {
		return nil, err
	}

	return &MigrationHandler{m}, nil
}

func (m *MigrationHandler) MigrationStep(step int) {
	var msg string
	if step > 0 {
		msg = "up"
	} else {
		msg = "down"
	}

	if err := m.Steps(step); err != nil {
		globals.LogAndExit(fmt.Sprintf("failed to run migration %s: %s", msg, err), 1)
	}
	ver, _, err := m.Version()
	if err != nil {
		globals.LogAndExit(err.Error(), 1)
	}
	globals.LogAndExit(fmt.Sprintf("successfully ran migration %s to version %d", msg, ver), 0)
}

func (m *MigrationHandler) RunMigrations() error {
	log.Info("Running database migrations")
	if err := m.Up(); err != nil {
		if strings.Contains(err.Error(), "no change") {
			log.Info("Database migration: NO CHANGE")
		} else {
			return err
		}
	} else {
		log.Info("Database migration: SUCCESS")
	}
	return nil
}

func ListMigrations() {
	var files []string
	if err := fs.WalkDir(&migrationFS, ".", func(path string, d fs.DirEntry, _ error) error {
		if d.IsDir() {
			return nil
		}
		files = append(files, path)
		return nil
	}); err != nil {
		globals.LogAndExit(err.Error(), 1)
	}
	for _, file := range files {
		fmt.Println(file)
	}
	os.Exit(0)
}

func ViewMigration(file string) []byte {
	f, _ := migrationFS.ReadFile(file)
	return f
}
