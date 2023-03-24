// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"

	dbm "github.com/undernetirc/cservice-api/db"
	"github.com/undernetirc/cservice-api/internal/checks"

	"github.com/undernetirc/cservice-api/internal/globals"

	"github.com/golang-jwt/jwt/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/jackc/pgx/v4/pgxpool"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/labstack/gommon/log"
	"github.com/redis/go-redis/v9"
	_ "github.com/swaggo/echo-swagger"
	echoSwagger "github.com/swaggo/echo-swagger"
	"github.com/undernetirc/cservice-api/controllers"
	_ "github.com/undernetirc/cservice-api/docs"
	"github.com/undernetirc/cservice-api/internal/config"
	"github.com/undernetirc/cservice-api/internal/helper"
	"github.com/undernetirc/cservice-api/internal/jwks"
	"github.com/undernetirc/cservice-api/models"
	"github.com/undernetirc/cservice-api/routes"
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
	pool, err := pgxpool.Connect(ctx, config.GetDbURI())
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

	// Initialize echo
	e := echo.New()
	e.Logger.SetLevel(log.DEBUG)
	e.Logger.SetOutput(os.Stdout)

	// Register validator
	validator := helper.NewValidator()
	e.Validator = validator

	// Middlewares
	e.Use(middleware.RequestID())
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// Load controllers
	healthCheckController := controllers.NewHealthCheckController(pool, rdb)
	authController := controllers.NewAuthenticationController(service, rdb, nil)
	userController := controllers.NewUserController(service)
	meController := controllers.NewMeController(service)

	// Load routes
	userRoutes := routes.NewUserRoute(userController)
	meRoutes := routes.NewMeRoute(meController)

	// Create JWKS if public and private keys algorithm is set
	if config.ServiceJWTSigningMethod.GetString() == "RS256" {
		pubJSJWKS, err := jwks.GenerateJWKS()
		if err != nil {
			log.Fatalf("failed to generate JWKS: %s", err)
		}
		e.GET("/.well-known/jwks.json", func(c echo.Context) error {
			return c.JSONBlob(http.StatusOK, pubJSJWKS)
		})
	}

	// JWT restricted API routes
	jwtConfig := echojwt.Config{
		SigningMethod: config.ServiceJWTSigningMethod.GetString(),
		SigningKey:    helper.GetJWTPublicKey(),
		NewClaimsFunc: func(c echo.Context) jwt.Claims {
			return new(helper.JwtClaims)
		},
	}

	prefixV1 := strings.Join([]string{config.ServiceApiPrefix.GetString(), "v1"}, "/")

	// API documentation (swagger)
	e.GET("/documentation/*", echoSwagger.WrapHandler)

	// Health check to determine if the service is up (useful for load balancers or k8s)
	e.GET("/health-check", healthCheckController.HealthCheck)

	// Authentication routes
	e.POST(fmt.Sprintf("%s/authn", prefixV1), authController.Login)
	e.POST(fmt.Sprintf("%s/authn/logout", prefixV1), authController.Logout, echojwt.WithConfig(jwtConfig))
	e.POST(fmt.Sprintf("%s/authn/refresh", prefixV1), authController.RefreshToken)
	e.POST(fmt.Sprintf("%s/authn/factor_verify", prefixV1), authController.VerifyFactor)
	e.POST(fmt.Sprintf("%s/authn/register", prefixV1), authController.Register)

	// Set up routes requiring valid JWT
	router := e.Group(prefixV1)
	router.Use(echojwt.WithConfig(jwtConfig))

	// User routes
	userRoutes.UserRoute(router)
	meRoutes.MeRoute(router)

	e.Logger.Fatal(e.Start(config.GetServerAddress()))
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
	}
}
