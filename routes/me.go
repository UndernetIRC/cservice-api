// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package routes

import (
	"github.com/labstack/echo/v4"
	"github.com/undernetirc/cservice-api/controllers"
)

type MeRoutes struct {
	MeController *controllers.MeController
}

func NewMeRoute(meController *controllers.MeController) *MeRoutes {
	return &MeRoutes{MeController: meController}
}

func (uc *MeRoutes) MeRoute(e *echo.Group) {
	router := e.Group("/me")
	router.GET("", uc.MeController.GetMe)
}
