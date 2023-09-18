// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	dbm "github.com/undernetirc/cservice-api/db"
	"github.com/undernetirc/cservice-api/internal/checks"
	"github.com/undernetirc/cservice-api/routes"

	"github.com/undernetirc/cservice-api/internal/globals"

	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/gommon/log"
	"github.com/redis/go-redis/v9"
	_ "github.com/swaggo/echo-swagger"
	"github.com/undernetirc/cservice-api/internal/config"
	_ "github.com/undernetirc/cservice-api/internal/docs"
	"github.com/undernetirc/cservice-api/models"
)

var (
	Version     = "0.0.1-dev"
	BuildDate   string
	BuildCommit string
)

func init() {
	configPath := flag.String("config", "", "directory path to configuration file")
	migrateUpOne := flag.Bool("migrate-up1", false, "run database migrations up by one and then exit")
	migrateDownOne := flag.Bool("migrate-down1", false, "run database migrations down by one and then exit")
	listMigrationFlag := flag.Bool("list-migrations", false, "list all SQL migrations and then exit")
	viewMigrationFlag := flag.String("view-migration", "", "view a specific SQL migration and then exit")
	versionFlag := flag.Bool("version", false, "print version and exit")

	flag.Parse()

	if *versionFlag {
		if BuildCommit == "" {
			BuildCommit = "unknown"
		}

		fmt.Printf("Version %s %s %s\n", Version, BuildCommit, BuildDate)
		os.Exit(0)
	}

	// Initialize configuration
	config.InitConfig(*configPath)

	mgrHandler, err := dbm.NewMigrationHandler()
	if err != nil {
		globals.LogAndExit(err.Error(), 1)
	}

	if *listMigrationFlag {
		mgrHandler.ListMigrations()
	}

	if *viewMigrationFlag != "" {
		sqlFile := mgrHandler.ViewMigration(*viewMigrationFlag)
		globals.LogAndExit(string(sqlFile), 0)
	}

	if *migrateUpOne && *migrateDownOne {
		globals.LogAndExit("cannot run migrations for both up and down at the same time", 1)
	}

	if *migrateUpOne {
		mgrHandler.MigrationStep(1)
	}

	if *migrateDownOne {
		mgrHandler.MigrationStep(-1)
	}

	// Run db migrations
	if config.DatabaseAutoMigration.GetBool() {
		if err := mgrHandler.RunMigrations(); err != nil {
			log.Fatalf("Migrations failed: %s", err)
			os.Exit(1)
		}
	}
}

func run() error {
	ctx := context.Background()

	// Connect to database
	pool, err := pgxpool.New(ctx, config.GetDbURI())
	if err != nil {
		log.Fatalf("failed to connect to the postgres database: %s", err)
	}
	defer pool.Close()
	db := models.New(pool)
	log.Info("Successfully connected to the postgres database")

	// Connect to redis
	rdb := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%s", config.RedisHost.GetString(), config.RedisPort.GetString()),
		Password: config.RedisPassword.GetString(),
		DB:       config.RedisDatabase.GetInt(),
	})
	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Fatalf("failed to connect to the redis database: %s", err)
	}
	defer func(rdb *redis.Client) {
		err := rdb.Close()
		if err != nil {
			log.Fatalf("failed to close redis client: %s", err)
		}
	}(rdb)
	log.Info("Successfully connected to redis")

	// Create service
	service := models.NewService(db)

	// Initialize checks
	checks.InitChecks(ctx, service)

	// Initialize echo framework and routes
	e := routes.NewEcho()
	r := routes.NewRouteService(e, service, pool, rdb)
	if err := routes.LoadRoutes(r); err != nil {
		return err
	}

	return nil
}

// @title UnderNET Channel Service API
// @version 0.1
// @description ...

// @contact.name Ratler
// @contact.email ratler@undernet.org

// @license.name MIT
// @license.url  https://github.com/UndernetIRC/cservice-api/blob/master/LICENSE

// @host localhost:8080
// @basePath /api/v1
func main() {
	if err := run(); err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
}
