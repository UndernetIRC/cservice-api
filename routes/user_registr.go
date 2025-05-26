// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

// Package routes defines the routes for the echo server.
package routes

import (
	"fmt"
	"strings"

	"github.com/labstack/gommon/log"
	"github.com/undernetirc/cservice-api/controllers"
	"github.com/undernetirc/cservice-api/internal/config"
)

// MeRoutes defines the routes for the me endpoints
func (r *RouteService) UserRegisterRoutes() {
	log.Info("Loading UserRegister routes")
	c := controllers.NewUserRegisterController(r.service, r.pool)

	prefixV1 := strings.Join([]string{config.ServiceAPIPrefix.GetString(), "v1"}, "/")

	r.e.POST(fmt.Sprintf("%s/register", prefixV1), c.UserRegister)
	r.e.POST(fmt.Sprintf("%s/activate", prefixV1), c.UserActivateAccount)
}
