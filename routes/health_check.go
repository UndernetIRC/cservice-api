// SPDX-License-Identifier: MIT
// SPDX-FileCopyRightText: Copyright (c) 2023 UnderNET

// Package routes defines the routes for the echo server.
package routes

import (
	"github.com/labstack/gommon/log"
	"github.com/undernetirc/cservice-api/controllers"
)

// HealthCheckRoutes Adds health check endpoint to determine if the service is up (useful for load balancers or k8s)
func (r *RouteService) HealthCheckRoutes() {
	if r.pool != nil {
		log.Info("Loading health check routes")
		c := controllers.NewHealthCheckController(r.pool, r.rdb)
		r.e.GET("/health-check", c.HealthCheck)
	}
}
