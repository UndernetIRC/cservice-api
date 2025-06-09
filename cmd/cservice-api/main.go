// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	slogformatter "github.com/samber/slog-formatter"
	_ "github.com/swaggo/echo-swagger"

	dbm "github.com/undernetirc/cservice-api/db"
	"github.com/undernetirc/cservice-api/internal/checks"
	"github.com/undernetirc/cservice-api/internal/config"
	"github.com/undernetirc/cservice-api/internal/cron"
	_ "github.com/undernetirc/cservice-api/internal/docs"
	"github.com/undernetirc/cservice-api/internal/globals"
	"github.com/undernetirc/cservice-api/internal/mail"
	"github.com/undernetirc/cservice-api/internal/metrics"
	"github.com/undernetirc/cservice-api/internal/telemetry"
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
	configFile        string
	migrateUpOne      bool
	migrateDownOne    bool
	forceMigration    int
	listMigrationFlag bool
	viewMigrationFlag string
	versionFlag       bool
)

// ShutdownManager manages graceful shutdown of all services
type ShutdownManager struct {
	logger            *slog.Logger
	server            *http.Server
	pool              *pgxpool.Pool
	rdb               *redis.Client
	wg                *sync.WaitGroup
	mailStop          chan struct{}
	cronService       *cron.Service
	telemetryProvider *telemetry.Provider
	systemMetrics     *metrics.SystemHealthMetrics
	instrumentedMail  *mail.InstrumentedMailService
}

// NewShutdownManager creates a new shutdown manager
func NewShutdownManager(logger *slog.Logger) *ShutdownManager {
	return &ShutdownManager{
		logger:   logger,
		wg:       &sync.WaitGroup{},
		mailStop: make(chan struct{}),
	}
}

// GracefulShutdown handles graceful shutdown of all services
func (sm *ShutdownManager) GracefulShutdown(shutdownTimeout time.Duration) {
	sm.logger.Info("Starting graceful shutdown...")

	// Create a context with timeout for shutdown operations
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	// Stop cron service first
	if sm.cronService != nil {
		sm.logger.Info("Stopping cron service...")
		sm.cronService.Stop()
		sm.logger.Info("Cron service stopped successfully")
	}

	// Stop telemetry provider
	if sm.telemetryProvider != nil {
		sm.logger.Info("Shutting down telemetry provider...")
		if err := sm.telemetryProvider.Shutdown(ctx); err != nil {
			sm.logger.Error("Error during telemetry shutdown", "error", err)
		} else {
			sm.logger.Info("Telemetry provider shut down successfully")
		}
	}

	// Stop accepting new HTTP requests and close existing connections
	if sm.server != nil {
		sm.logger.Info("Shutting down HTTP server...")
		if err := sm.server.Shutdown(ctx); err != nil {
			sm.logger.Error("Error during HTTP server shutdown", "error", err)
		} else {
			sm.logger.Info("HTTP server shut down successfully")
		}
	}

	// Signal mail workers to stop and wait for them to finish processing
	if config.ServiceMailEnabled.GetBool() && mail.MailQueue != nil {
		sm.logger.Info("Stopping mail workers...")
		close(sm.mailStop)

		// Close mail queue to signal workers to stop after processing pending emails
		close(mail.MailQueue)
		sm.logger.Info("Mail queue closed, waiting for workers to finish...")
	}

	// Wait for all background goroutines to finish
	done := make(chan struct{})
	go func() {
		sm.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		sm.logger.Info("All background services stopped successfully")
	case <-ctx.Done():
		sm.logger.Warn("Shutdown timeout reached, some services may not have stopped gracefully")
	}

	// Close database connections
	if sm.pool != nil {
		sm.logger.Info("Closing database connections...")
		sm.pool.Close()
		sm.logger.Info("Database connections closed")
	}

	// Close Redis connections
	if sm.rdb != nil {
		sm.logger.Info("Closing Redis connections...")
		if err := sm.rdb.Close(); err != nil {
			sm.logger.Error("Error closing Redis connections", "error", err)
		} else {
			sm.logger.Info("Redis connections closed")
		}
	}

	sm.logger.Info("Graceful shutdown completed")
}

func init() {
	flag.StringVar(&configFile, "config", "", "path to configuration file")
	flag.BoolVar(&migrateUpOne, "migrate-up1", false, "run database migrations up by one and then exit")
	flag.BoolVar(&migrateDownOne, "migrate-down1", false, "run database migrations down by one and then exit")
	flag.IntVar(&forceMigration, "force-migration", 0, "force database migration to a specific version and then exit")
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

	if config.DatabaseAutoMigration.GetBool() || migrateUpOne || migrateDownOne || forceMigration > 0 {
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

	if forceMigration > 0 {
		mgrHandler.ForceVersion(forceMigration)
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

	// Setup slog handler
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

	// Initialize shutdown manager
	shutdownManager := NewShutdownManager(logger)

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Load default config
	config.InitConfig(configFile)

	// Apply migrations if any
	runMigrations()

	// Initialize mail queue only if mail is enabled (workers will be started later)
	var mailErr chan error
	if config.ServiceMailEnabled.GetBool() {
		// Initialize mail template engine
		templateEngine := mail.GetTemplateEngine()
		if err := templateEngine.Init(); err != nil {
			logger.Warn("Failed to initialize mail template engine", "error", err)
		} else {
			logger.Info("Mail template engine initialized", "templateDir", config.ServiceMailTemplateDir.GetString())
		}

		mail.MailQueue = make(chan mail.Mail, 100)
		mailErr = make(chan error, 100)
		MailWorker = config.ServiceMailWorkers.GetInt()

		logger.Info("Mail service initialized", "workers", MailWorker, "queueSize", 100)

		// Start error handler goroutine to log mail errors
		shutdownManager.wg.Add(1)
		go func() {
			defer shutdownManager.wg.Done()
			defer func() {
				if mailErr != nil {
					close(mailErr)
				}
			}()

			for {
				select {
				case err := <-mailErr:
					if err != nil {
						logger.Error("Mail processing failed", "error", err)
					}
				case <-shutdownManager.mailStop:
					logger.Info("Mail error handler stopping...")
					return
				}
			}
		}()
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
	shutdownManager.pool = pool
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
	shutdownManager.rdb = rdb
	logger.Info("Successfully connected to redis", "db", config.RedisDatabase.GetString(),
		"host", config.RedisHost.GetString(), "port", config.RedisPort.GetInt(),
	)

	// Create service
	service := models.NewService(db)

	// Initialize checks
	checks.InitChecks(ctx, service)

	// Initialize telemetry provider if enabled
	var telemetryProvider *telemetry.Provider
	if config.TelemetryEnabled.GetBool() {
		telemetryConfig, err := telemetry.LoadConfigFromViper()
		if err != nil {
			logger.Error("failed to load telemetry config", "error", err)
			return err
		}

		telemetryProvider, err = telemetry.InitializeWithConfig(ctx, telemetryConfig)
		if err != nil {
			logger.Error("failed to initialize telemetry provider", "error", err)
			return err
		}
		shutdownManager.telemetryProvider = telemetryProvider
		logger.Info("Telemetry provider initialized successfully")
	}

	// Initialize system health metrics if telemetry is enabled
	var systemMetrics *metrics.SystemHealthMetrics
	var instrumentedMail *mail.InstrumentedMailService
	if telemetryProvider != nil && telemetryProvider.IsEnabled() {
		// Create system health metrics
		systemMetricsConfig := metrics.SystemHealthMetricsConfig{
			Meter:       telemetryProvider.GetMeter("cservice-api"),
			ServiceName: "cservice-api",
		}

		systemMetrics, err = metrics.NewSystemHealthMetrics(systemMetricsConfig)
		if err != nil {
			logger.Error("failed to create system health metrics", "error", err)
			return err
		}
		shutdownManager.systemMetrics = systemMetrics

		// Create instrumented mail service
		instrumentedMail = mail.NewInstrumentedMailService(systemMetrics)
		shutdownManager.instrumentedMail = instrumentedMail

		logger.Info("System health metrics initialized successfully")
	}

	// Initialize cron service
	cronConfig := cron.LoadServiceConfigFromViper()
	cronService, err := cron.NewService(cronConfig, logger)
	if err != nil {
		logger.Error("failed to create cron service", "error", err)
		return err
	}
	shutdownManager.cronService = cronService

	// Replace cron scheduler with instrumented version if system metrics are available
	if systemMetrics != nil && cronService.IsEnabled() {
		// Create instrumented cron scheduler
		schedulerConfig := cron.Config{
			PasswordResetCleanupCron: cronConfig.PasswordResetCleanupCron,
			TimeZone:                 cronConfig.TimeZone,
		}

		instrumentedScheduler, err := cron.NewInstrumentedScheduler(schedulerConfig, logger, systemMetrics)
		if err != nil {
			logger.Error("failed to create instrumented cron scheduler", "error", err)
			return err
		}

		// Note: We would need to modify the cron.Service to accept an instrumented scheduler
		// For now, we'll just log that we have the capability
		logger.Info("Instrumented cron scheduler created (integration pending)")
		_ = instrumentedScheduler // Prevent unused variable error
	}

	// Setup password reset cleanup job if cron service is enabled
	if cronService.IsEnabled() {
		if err := cronService.SetupPasswordResetCleanup(db, cronConfig); err != nil {
			logger.Error("failed to setup password reset cleanup job", "error", err)
			return err
		}

		// Start the cron service
		if err := cronService.Start(); err != nil {
			logger.Error("failed to start cron service", "error", err)
			return err
		}

		logger.Info("Cron service started successfully", "jobs", len(cronService.GetJobEntries()))
	}

	// Start mail workers if mail is enabled
	if config.ServiceMailEnabled.GetBool() && mail.MailQueue != nil {
		shutdownManager.wg.Add(1)
		go func() {
			defer shutdownManager.wg.Done()
			// Use instrumented mail workers if available, otherwise use regular workers
			if instrumentedMail != nil {
				instrumentedMail.StartInstrumentedMailWorkers(mail.MailQueue, mailErr, MailWorker)
				logger.Info("Instrumented mail workers started", "count", MailWorker)
			} else {
				mail.MailWorker(mail.MailQueue, mailErr, MailWorker)
				logger.Info("Regular mail workers started", "count", MailWorker)
			}
			logger.Info("Mail workers stopped")
		}()
	}

	// Initialize echo framework and routes
	e := routes.NewEcho()
	var r *routes.RouteService
	if telemetryProvider != nil {
		r = routes.NewRouteServiceWithTelemetry(e, service, pool, rdb, telemetryProvider)
	} else {
		r = routes.NewRouteService(e, service, pool, rdb)
	}

	// Load routes but don't start the server yet
	if err := routes.LoadRoutesWithOptions(r, false); err != nil {
		return err
	}

	// Create HTTP server with proper configuration
	server := &http.Server{
		Addr:              config.GetServerAddress(),
		Handler:           e,
		ReadHeaderTimeout: time.Duration(config.ServiceHTTPReadHeaderTimeoutSeconds.GetInt()) * time.Second,
		ReadTimeout:       time.Duration(config.ServiceHTTPReadTimeoutSeconds.GetInt()) * time.Second,
		WriteTimeout:      time.Duration(config.ServiceHTTPWriteTimeoutSeconds.GetInt()) * time.Second,
		IdleTimeout:       time.Duration(config.ServiceHTTPIdleTimeoutSeconds.GetInt()) * time.Second,
	}
	shutdownManager.server = server

	// Start server in a goroutine
	shutdownManager.wg.Add(1)
	go func() {
		defer shutdownManager.wg.Done()
		logger.Info("Starting server", "address", config.GetServerAddress())
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("Server error", "error", err)
		}
	}()

	// Wait for shutdown signal
	sig := <-sigChan
	logger.Info("Received shutdown signal", "signal", sig.String())

	// Perform graceful shutdown with configurable timeout
	shutdownTimeout := time.Duration(config.ServiceShutdownTimeoutSeconds.GetInt()) * time.Second
	shutdownManager.GracefulShutdown(shutdownTimeout)

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
