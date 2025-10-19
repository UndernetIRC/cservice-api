// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 - 2025 UnderNET

// Package routes defines the routes for the echo server.
package routes

import (
	"github.com/labstack/gommon/log"
	"github.com/undernetirc/cservice-api/controllers"
	"github.com/undernetirc/cservice-api/internal/helper"
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
	userRouter.POST("/2fa/enroll", c.EnrollTOTP)
	userRouter.POST("/2fa/activate", c.ActivateTOTP)
	userRouter.POST("/2fa/disable", c.DisableTOTP)
	userRouter.PUT("/backup-codes/mark-read", c.MarkBackupCodesAsRead)
	userRouter.POST("/backup-codes", c.RegenerateBackupCodes)

	// Admin user endpoints (requires authorization)
	usersRouter := r.routerGroup.Group("/users", middlewares.HasAuthorization(1000, helper.ScopeUsersRead))
	usersRouter.GET("/:id", c.GetUser)
	usersRouter.GET("/:id/roles", c.GetUserRoles)
}
