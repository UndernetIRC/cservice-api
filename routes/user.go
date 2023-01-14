// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package routes

import (
	"github.com/labstack/echo/v4"
	"github.com/undernetirc/cservice-api/controllers"
)

type UserRoutes struct {
	UserController *controllers.UserController
}

func NewUserRoute(userController *controllers.UserController) *UserRoutes {
	return &UserRoutes{UserController: userController}
}

func (uc *UserRoutes) UserRoute(e *echo.Group) {
	router := e.Group("/users")
	router.GET("/:id", uc.UserController.GetUser)
}
