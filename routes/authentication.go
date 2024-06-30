// SPDX-License-Identifier: MIT
// SPDX-FileCopyRightText: Copyright (c) 2023 UnderNET

// Package routes defines the routes for the echo server.
package routes

import (
	"fmt"
	"strings"

	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/gommon/log"

	"github.com/undernetirc/cservice-api/controllers"
	"github.com/undernetirc/cservice-api/internal/config"
	"github.com/undernetirc/cservice-api/internal/helper"
)

// AuthnRoutes defines the routes for the authentication endpoints
func (r *RouteService) AuthnRoutes() {
	log.Info("Loading authentication routes")
	c := controllers.NewAuthenticationController(r.service, r.rdb, nil)

	prefixV1 := strings.Join([]string{config.ServiceApiPrefix.GetString(), "v1"}, "/")

	// Authentication routes
	r.e.POST(fmt.Sprintf("%s/login", prefixV1), c.Login)
	r.e.POST(fmt.Sprintf("%s/logout", prefixV1), c.Logout, echojwt.WithConfig(helper.GetEchoJWTConfig()))
	r.e.POST(fmt.Sprintf("%s/authn/refresh", prefixV1), c.RefreshToken)
	r.e.POST(fmt.Sprintf("%s/authn/factor_verify", prefixV1), c.VerifyFactor)
	r.e.POST(fmt.Sprintf("%s/register", prefixV1), c.Register)
}
