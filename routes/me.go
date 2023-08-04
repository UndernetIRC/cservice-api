// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

// Package routes defines the routes for the echo server.
package routes

import (
	"github.com/labstack/gommon/log"
	"github.com/undernetirc/cservice-api/controllers"
)

// MeRoutes defines the routes for the me endpoints
func (r *RouteService) MeRoutes() {
	log.Info("Loading me routes")
	c := controllers.NewMeController(r.service)
	router := r.routerGroup.Group("/me")
	router.GET("", c.GetMe)
}
