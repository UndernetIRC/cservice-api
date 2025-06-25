// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 - 2025 UnderNET

// Package routes defines the routes for the echo server.
package routes

import (
	"github.com/labstack/gommon/log"
	"github.com/undernetirc/cservice-api/controllers"
)

// ChannelRoutes defines the routes for the channel endpoints
func (r *RouteService) ChannelRoutes() {
	log.Info("Loading channel routes")
	c := controllers.NewChannelController(r.service, r.pool)

	// Channel endpoints (requires JWT authentication)
	channelRouter := r.routerGroup.Group("/channels")
	channelRouter.GET("/search", c.SearchChannels)
	channelRouter.POST("", c.RegisterChannel)
	channelRouter.GET("/:id", c.GetChannelSettings)
	channelRouter.PUT("/:id", c.UpdateChannelSettings)
	channelRouter.POST("/:id/members", c.AddChannelMember)
	channelRouter.POST("/:id/manager-change", c.RequestManagerChange)
	channelRouter.GET("/:id/manager-confirm", c.ConfirmManagerChange)
}
