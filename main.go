package main

import (
	"context"
	"embed"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/go-redis/redis/v9"
	"github.com/golang-jwt/jwt/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/jackc/pgx/v4/pgxpool"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/labstack/gommon/log"
	_ "github.com/swaggo/echo-swagger"
	echoSwagger "github.com/swaggo/echo-swagger"
	"github.com/undernetirc/cservice-api/controllers"
	_ "github.com/undernetirc/cservice-api/docs"
	"github.com/undernetirc/cservice-api/internal/config"
	"github.com/undernetirc/cservice-api/internal/helper"
	"github.com/undernetirc/cservice-api/internal/jwks"
	"github.com/undernetirc/cservice-api/internal/migration"
	"github.com/undernetirc/cservice-api/middlewares"
	"github.com/undernetirc/cservice-api/models"
	"github.com/undernetirc/cservice-api/routes"
)

//go:embed db/migrations/*.sql
var sqlFs embed.FS

var (
	Version     = "0.0.1-dev"
	BuildDate   string
	BuildCommit string
)

func init() {
	configFile := flag.String("config", "config.yml", "path to configuration file")
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

	config.LoadConfig(configFile)

	mgrHandler, err := migration.NewMigrationHandler(&sqlFs)
	if err != nil {
		helper.LogAndExit(err.Error(), 1)
	}

	if *listMigrationFlag {
		mgrHandler.ListMigrations()
	}

	if *viewMigrationFlag != "" {
		sqlFile, _ := sqlFs.ReadFile(*viewMigrationFlag)
		helper.LogAndExit(string(sqlFile), 0)
	}

	if *migrateUpOne && *migrateDownOne {
		helper.LogAndExit("cannot run migrations for both up and down at the same time", 1)
	}

	if *migrateUpOne {
		mgrHandler.MigrationStep(1)
	}

	if *migrateDownOne {
		mgrHandler.MigrationStep(-1)
	}

	// Run db migrations
	if config.Conf.Database.AutoMigration {
		if err := mgrHandler.RunMigrations(); err != nil {
			log.Fatalf("Migrations failed: %s", err)
			os.Exit(1)
		}
	}
}

func run() error {
	ctx := context.Background()

	// Connect to database
	pool, err := pgxpool.Connect(ctx, config.Conf.GetDbURI())
	if err != nil {
		log.Fatalf("failed to connect to the postgres database: %s", err)
	}
	defer pool.Close()
	db := models.New(pool)
	log.Info("Successfully connected to the postgres database")

	// Connect to redis
	rdb := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", config.Conf.Redis.Host, config.Conf.Redis.Port),
		Password: config.Conf.Redis.Password,
		DB:       config.Conf.Redis.Database,
	})
	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Fatalf("failed to connect to the redis database: %s", err)
	}
	log.Info("Successfully connected to redis")

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

	service := models.NewService(db)

	// Load controllers
	healthCheckController := controllers.NewHealthCheckController(pool, rdb)
	authController := controllers.NewAuthenticationController(service, rdb)
	userController := controllers.NewUserController(service)
	meController := controllers.NewMeController(service)

	// Load routes
	userRoutes := routes.NewUserRoute(userController)
	meRoutes := routes.NewMeRoute(meController)

	// Create JWKS if public and private keys algorithm is set
	if config.Conf.JWT.SigningMethod == "RS256" {
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
		SigningMethod: config.Conf.JWT.SigningMethod,
		SigningKey:    config.Conf.GetJWTPublicKey(),
		NewClaimsFunc: func(c echo.Context) jwt.Claims {
			return new(helper.JwtClaims)
		},
	}

	// API documentation (swagger)
	e.GET("/documentation/*", echoSwagger.WrapHandler)

	// Health check to determine if the service is up (useful for load balancers or k8s)
	e.GET("/health-check", healthCheckController.HealthCheck)

	// Authentication routes
	e.POST("/login", authController.Login)
	e.POST("/logout", authController.Logout, echojwt.WithConfig(jwtConfig))
	e.POST("/token/refresh", authController.RefreshToken)
	e.POST("/validate-otp", authController.ValidateOTP, echojwt.WithConfig(jwtConfig))

	// Set up routes requiring authentication
	prefixV1 := strings.Join([]string{config.Conf.Server.ApiPrefix, "v1"}, "/")
	router := e.Group(prefixV1)
	router.Use(echojwt.WithConfig(jwtConfig))
	router.Use(middlewares.JWTIsAuthenticated)

	// User routes
	userRoutes.UserRoute(router)
	meRoutes.MeRoute(router)

	e.Logger.Fatal(e.Start(":8080"))
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
