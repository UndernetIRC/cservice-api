// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

// Package routes defines the routes for the echo server.
package routes

import (
	"github.com/labstack/gommon/log"
	"github.com/undernetirc/cservice-api/controllers"
	"github.com/undernetirc/cservice-api/middlewares"
)

// UserRoutes defines the routes for the user endpoints
func (r *RouteService) UserRoutes() {
	log.Info("Loading user routes")
	c := controllers.NewUserController(r.service)
	router := r.routerGroup.Group("/users", middlewares.HasAuthorization(1000))
	router.GET("/:id", c.GetUser)
	router.GET("/:id/roles", c.GetUserRoles)
}
