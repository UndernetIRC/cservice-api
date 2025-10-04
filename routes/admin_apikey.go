// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

package routes

import (
	"github.com/labstack/gommon/log"
	"github.com/undernetirc/cservice-api/controllers/admin"
	"github.com/undernetirc/cservice-api/middlewares"
)

// APIKeyRoutes defines the routes for API key management endpoints
func (r *RouteService) AdminAPIKeyRoutes() {
	log.Info("Loading API key routes")
	c := admin.NewAPIKeyController(r.service)

	// Available scopes endpoint (any authenticated user can view)
	apiKeysRouter := r.routerGroup.Group("/admin/api-keys")
	apiKeysRouter.GET("/scopes", c.GetAvailableScopes)

	// API key management requires level 1000+ (admin only)
	adminRouter := apiKeysRouter.Group("", middlewares.HasAuthorization(1000))
	adminRouter.POST("", c.CreateAPIKey)
	adminRouter.GET("", c.ListAPIKeys)
	adminRouter.GET("/:id", c.GetAPIKey)
	adminRouter.PUT("/:id/scopes", c.UpdateAPIKeyScopes)
	adminRouter.DELETE("/:id", c.DeleteAPIKey)
}
