// SPDX-License-Identifier: MIT
// SPDX-FileCopyRightText: Copyright (c) 2023 UnderNET

// Package routes defines the routes for the echo server.
package routes

import (
	"net/http"
	"os"
	"reflect"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/labstack/gommon/log"
	"github.com/mvrilo/go-redoc"
	echoredoc "github.com/mvrilo/go-redoc/echo"
	"github.com/redis/go-redis/v9"
	"github.com/undernetirc/cservice-api/internal/config"
	"github.com/undernetirc/cservice-api/internal/docs"
	"github.com/undernetirc/cservice-api/internal/helper"
	"github.com/undernetirc/cservice-api/internal/jwks"
	"github.com/undernetirc/cservice-api/models"
)

// RouteService is a struct that holds the echo instance, the echo group,
// the service, the database pool, and the redis client
type RouteService struct {
	e           *echo.Echo
	routerGroup *echo.Group
	service     models.Querier
	pool        *pgxpool.Pool
	rdb         *redis.Client
}

// NewRouteService creates a new RoutesService
func NewRouteService(e *echo.Echo, service models.Querier, pool *pgxpool.Pool, rdb *redis.Client) *RouteService {
	return &RouteService{
		e:       e,
		service: service,
		pool:    pool,
		rdb:     rdb,
	}
}

func NewEcho() *echo.Echo {
	// Initialize echo
	e := echo.New()
	e.HideBanner = true
	e.Logger.SetLevel(log.DEBUG)
	e.Logger.SetOutput(os.Stdout)
	e.Validator = helper.NewValidator()

	// Middlewares
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.RequestID())

	// CORS
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowCredentials: config.ServiceCorsAllowCredentials.GetBool(),
		AllowOrigins:     config.ServiceCorsAllowOrigins.GetStringSlice(),
		AllowMethods:     config.ServiceCorsAllowMethods.GetStringSlice(),
		MaxAge:           config.ServiceCorsMaxAge.GetInt(),
	}))

	// API documentation (swagger)
	doc := redoc.Redoc{
		DocsPath: "/docs",
		SpecPath: "/swagger.json",
		SpecFile: "swagger.json",
		SpecFS:   &docs.SwaggerFS,
		Title:    "CSservice API Documentation",
	}
	e.Use(echoredoc.New(doc))

	// Create JWKS if public and private keys algorithm is set
	if config.ServiceJWTSigningMethod.GetString() == "RS256" {
		pubJSJWKS, err := jwks.GenerateJWKS()
		if err != nil {
			log.Fatalf("failed to generate JWKS: %service", err)
		}
		e.GET("/.well-known/jwks.json", func(c echo.Context) error {
			return c.JSONBlob(http.StatusOK, pubJSJWKS)
		})
	}

	return e
}

// LoadRoutes loads the routes for the echo server
func LoadRoutes(r *RouteService) error {
	return LoadRoutesWithOptions(r, true)
}

// LoadRoutesWithOptions loads the routes for the echo server with additional options
func LoadRoutesWithOptions(r *RouteService, startServer bool) error {
	// Set up routes requiring valid JWT
	prefixV1 := strings.Join([]string{config.ServiceAPIPrefix.GetString(), "v1"}, "/")
	r.routerGroup = r.e.Group(prefixV1)
	r.routerGroup.Use(echojwt.WithConfig(helper.GetEchoJWTConfig()))

	// Load routes using reflection by looking for methods ending in "Routes"
	reflType := reflect.TypeOf(r)
	for i := 0; i < reflType.NumMethod(); i++ {
		method := reflType.Method(i)
		if strings.HasSuffix(method.Name, "Routes") {
			reflect.ValueOf(r).MethodByName(method.Name).Call(nil)
		}
	}

	// Start echo server if requested
	if startServer {
		if err := r.e.Start(config.GetServerAddress()); err != nil {
			return err
		}
	}

	return nil
}
