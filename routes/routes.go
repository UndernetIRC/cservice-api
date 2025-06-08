// SPDX-License-Identifier: MIT
// SPDX-FileCopyRightText: Copyright (c) 2023 UnderNET

// Package routes defines the routes for the echo server.
package routes

import (
	"fmt"
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
	"github.com/undernetirc/cservice-api/internal/telemetry"
	"github.com/undernetirc/cservice-api/middlewares"
	"github.com/undernetirc/cservice-api/models"
)

// RouteService is a struct that holds the echo instance, the echo group,
// the service, the database pool, and the redis client
type RouteService struct {
	e                 *echo.Echo
	routerGroup       *echo.Group
	service           models.ServiceInterface
	pool              *pgxpool.Pool
	rdb               *redis.Client
	telemetryProvider *telemetry.Provider
}

// NewRouteService creates a new RoutesService
func NewRouteService(
	e *echo.Echo,
	service models.ServiceInterface,
	pool *pgxpool.Pool,
	rdb *redis.Client,
) *RouteService {
	return &RouteService{
		e:       e,
		service: service,
		pool:    pool,
		rdb:     rdb,
	}
}

// NewRouteServiceWithTelemetry creates a new RoutesService with telemetry provider
func NewRouteServiceWithTelemetry(
	e *echo.Echo,
	service models.ServiceInterface,
	pool *pgxpool.Pool,
	rdb *redis.Client,
	telemetryProvider *telemetry.Provider,
) *RouteService {
	return &RouteService{
		e:                 e,
		service:           service,
		pool:              pool,
		rdb:               rdb,
		telemetryProvider: telemetryProvider,
	}
}

func NewEcho() *echo.Echo {
	// Initialize echo
	e := echo.New()
	e.HideBanner = true
	e.HidePort = true
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

	// Google ReCAPTCHA
	prefixV1 := strings.Join([]string{config.ServiceAPIPrefix.GetString(), "v1"}, "/")
	e.Use(middlewares.ReCAPTCHAWithConfig(middlewares.ReCAPTCHAConfig{
		Skipper: middlewares.ApplyReCAPTCHA(
			fmt.Sprintf("/%s/register", prefixV1),
			fmt.Sprintf("/%s/activate", prefixV1),
		),
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
	// Add telemetry middleware if telemetry is enabled
	if r.telemetryProvider != nil && r.telemetryProvider.IsEnabled() {
		cfg, err := telemetry.LoadConfigFromViper()
		if err == nil {
			// Setup global propagator for trace context
			middlewares.SetupGlobalPropagator()

			// Add HTTP tracing middleware if tracing is enabled
			if cfg.TracingEnabled {
				// Use the tracer provider directly for the middleware
				r.e.Use(middlewares.HTTPTracingEnhanced(r.telemetryProvider.GetTracerProvider(), cfg.ServiceName))

				// Add log correlation middleware after tracing to ensure trace context is available
				r.e.Use(middlewares.LogCorrelationWithConfig(middlewares.LogCorrelationConfig{
					IncludeRequestDetails: true, // Include request details in logs
				}))
			}

			// Add HTTP metrics middleware if metrics are enabled
			if cfg.MetricsEnabled {
				meter := r.telemetryProvider.GetMeter("cservice-api-http")
				r.e.Use(middlewares.HTTPInstrumentation(meter))
			}
		}
	}

	// Set up routes requiring valid JWT
	prefixV1 := strings.Join([]string{config.ServiceAPIPrefix.GetString(), "v1"}, "/")
	r.routerGroup = r.e.Group(prefixV1)
	r.routerGroup.Use(echojwt.WithConfig(helper.GetEchoJWTConfig()))

	// Register metrics endpoint if telemetry is enabled
	if r.telemetryProvider != nil && r.telemetryProvider.IsEnabled() {
		cfg, err := telemetry.LoadConfigFromViper()
		if err == nil && cfg.PrometheusEnabled {
			if err := telemetry.RegisterMetricsEndpoint(r.e, r.telemetryProvider, cfg); err != nil {
				log.Warnf("Failed to register metrics endpoint: %v", err)
			}
		}
	}

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
