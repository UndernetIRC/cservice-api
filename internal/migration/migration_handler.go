// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package migration

import (
	"embed"
	"fmt"
	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/labstack/gommon/log"
	"github.com/undernetirc/cservice-api/internal/config"
	"github.com/undernetirc/cservice-api/internal/helper"
	"io/fs"
	"os"
	"strings"
)

type MigrationHandler struct {
	m   *migrate.Migrate
	efs *embed.FS
}

func NewMigrationHandler(efs *embed.FS) (*MigrationHandler, error) {
	d, err := iofs.New(efs, "db/migrations")
	if err != nil {
		return nil, err
	}
	m, err := migrate.NewWithSourceInstance("iofs", d, config.Conf.GetDbURI())

	return &MigrationHandler{m: m, efs: efs}, nil
}

func (mgr *MigrationHandler) MigrationStep(step int) {
	var msg string
	if step > 0 {
		msg = "up"
	} else {
		msg = "down"
	}

	if err := mgr.m.Steps(step); err != nil {
		helper.LogAndExit(fmt.Sprintf("failed to run migration %s: %s", msg, err), 1)
	}
	ver, _, err := mgr.m.Version()
	if err != nil {
		helper.LogAndExit(err.Error(), 1)
	}
	helper.LogAndExit(fmt.Sprintf("successfully ran migration %s to version %d", msg, ver), 0)
}

func (mgr *MigrationHandler) ListMigrations() {
	var files []string
	if err := fs.WalkDir(mgr.efs, ".", func(path string, d fs.DirEntry, err error) error {
		if d.IsDir() {
			return nil
		}
		files = append(files, path)
		return nil
	}); err != nil {
		helper.LogAndExit(err.Error(), 1)
	}
	for _, file := range files {
		fmt.Println(file)
	}
	os.Exit(0)
}

func (mgr *MigrationHandler) RunMigrations() error {
	log.Info("Running database migrations")
	if err := mgr.m.Up(); err != nil {
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
