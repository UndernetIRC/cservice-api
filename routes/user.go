// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 - 2025 UnderNET

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

	// Current user endpoint (no authorization middleware needed as it uses JWT claims)
	userRouter := r.routerGroup.Group("/user")
	userRouter.GET("", c.GetCurrentUser)
	userRouter.PUT("/password", c.ChangePassword)

	// Admin user endpoints (requires authorization)
	usersRouter := r.routerGroup.Group("/users", middlewares.HasAuthorization(1000))
	usersRouter.GET("/:id", c.GetUser)
	usersRouter.GET("/:id/roles", c.GetUserRoles)
}
