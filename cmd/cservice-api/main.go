// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	slogformatter "github.com/samber/slog-formatter"
	_ "github.com/swaggo/echo-swagger"

	dbm "github.com/undernetirc/cservice-api/db"
	"github.com/undernetirc/cservice-api/internal/checks"
	"github.com/undernetirc/cservice-api/internal/config"
	_ "github.com/undernetirc/cservice-api/internal/docs"
	"github.com/undernetirc/cservice-api/internal/globals"
	"github.com/undernetirc/cservice-api/internal/mail"
	"github.com/undernetirc/cservice-api/models"
	"github.com/undernetirc/cservice-api/routes"
)

var (
	Version     = "0.0.1-dev"
	BuildDate   string
	BuildCommit string

	BufferSize = 20

	MailWorker int
)

// Flags
var (
	configPath        string
	migrateUpOne      bool
	migrateDownOne    bool
	listMigrationFlag bool
	viewMigrationFlag string
	versionFlag       bool
)

func init() {
	flag.StringVar(&configPath, "config-path", "", "directory path to configuration file")
	flag.BoolVar(&migrateUpOne, "migrate-up1", false, "run database migrations up by one and then exit")
	flag.BoolVar(&migrateDownOne, "migrate-down1", false, "run database migrations down by one and then exit")
	flag.BoolVar(&listMigrationFlag, "list-migrations", false, "list all SQL migrations and then exit")
	flag.StringVar(&viewMigrationFlag, "view-migration", "", "view a specific SQL migration and then exit")
	flag.BoolVar(&versionFlag, "version", false, "print version and exit")

	flag.Parse()

	if listMigrationFlag {
		files, err := dbm.ListMigrations()
		if err != nil {
			globals.LogAndExit(err.Error(), 1)
		}
		for _, file := range files {
			fmt.Println(file)
		}
		os.Exit(0)
	}

	if viewMigrationFlag != "" {
		sqlFile := dbm.ViewMigration(viewMigrationFlag)
		globals.LogAndExit(string(sqlFile), 0)
	}

	if versionFlag {
		if BuildCommit == "" {
			BuildCommit = "unknown"
		}

		fmt.Printf("Version %s %s %s\n", Version, BuildCommit, BuildDate)
		os.Exit(0)
	}
}

func runMigrations() {
	var mgrHandler *dbm.MigrationHandler
	var err error

	if config.DatabaseAutoMigration.GetBool() || migrateUpOne || migrateDownOne {
		mgrHandler, err = dbm.NewMigrationHandler()
		if err != nil {
			globals.LogAndExit(err.Error(), 1)
		}
	} else {
		return
	}

	if migrateUpOne && migrateDownOne {
		globals.LogAndExit("cannot run migrations for both up and down at the same time", 1)
	}

	if migrateUpOne {
		mgrHandler.MigrationStep(1)
	}

	if migrateDownOne {
		mgrHandler.MigrationStep(-1)
	}

	// Run db migrations
	if config.DatabaseAutoMigration.GetBool() {
		if err := mgrHandler.RunMigrations(); err != nil {
			slog.Error("Migrations failed", "error", err)
			os.Exit(1)
		}
	}
}

func run() error {
	ctx := context.Background()

	// Setup slog hadler
	handler := slog.NewJSONHandler(os.Stdout, nil)
	logger := slog.New(
		slogformatter.NewFormatterHandler(
			slogformatter.TimezoneConverter(time.UTC),
			slogformatter.TimeFormatter(time.RFC3339, nil),
		)(
			handler,
		),
	)
	slog.SetDefault(logger)

	// Load default config
	config.InitConfig(configPath)

	// Apply migrations if any
	runMigrations()

	// Initialize mail queue and workers only if mail is enabled
	if config.ServiceMailEnabled.GetBool() {
		mail.MailQueue = make(chan mail.Mail, 100)
		mailErr := make(chan error, 100)
		MailWorker = config.ServiceMailWorkers.GetInt()
		go mail.MailWorker(mail.MailQueue, mailErr, MailWorker)
		defer close(mail.MailQueue)
	}

	// Connect to database
	pool, err := pgxpool.New(ctx, config.GetDbURI())
	if err != nil {
		logger.Error("failed to create a PGX pool", "error", err)
		return err
	}
	if err := pool.Ping(ctx); err != nil {
		logger.Error("failed to connect to PostgreSQL DB", "error", err)
		return err
	}
	defer pool.Close()
	db := models.New(pool)
	logger.Info(
		"Successfully connected to the PostgreSQL",
		"db",
		config.DatabaseName.GetString(),
		"host",
		config.DatabaseHost.GetString(),
		"port",
		config.DatabasePort.GetInt(),
	)

	// Connect to redis
	rdb := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%s", config.RedisHost.GetString(), config.RedisPort.GetString()),
		Password: config.RedisPassword.GetString(),
		DB:       config.RedisDatabase.GetInt(),
	})
	if err := rdb.Ping(ctx).Err(); err != nil {
		logger.Error("failed to connect to the redis database", "error", err)
		return err
	}
	defer func(rdb *redis.Client) {
		err := rdb.Close()
		if err != nil {
			logger.Error("failed to close redis client", "error", err)
		}
	}(rdb)
	logger.Info("Successfully connected to redis", "db", config.RedisDatabase.GetString(),
		"host", config.RedisHost.GetString(), "port", config.RedisPort.GetInt(),
	)

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
// @description This is the API for the UnderNET Channel Service. It provides a RESTful interface for managing users, channels, and other resources. <!-- ReDoc-Inject: <security-definitions> -->
// @description # Authorization
// @description **JWT Bearer Token:** The main authorization method for the API. Needs `Authorization: Bearer <jwt-token>` HTTP header to authenticate.
// @description <!-- ReDoc-Inject: <security-definitions> -->

// @contact.name Ratler
// @contact.email ratler@undernet.org

// @license.name MIT
// @license.url  https://github.com/UndernetIRC/cservice-api/blob/master/LICENSE

// @host localhost:8080
// @basePath /api/v1

// @securityDefinitions.apikey JWTBearerToken
// @in header
// @name Authorization
func main() {
	if err := run(); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}
