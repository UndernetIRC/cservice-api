// SPDX-License-Identifier: MIT
// SPDX-FileCopyRightText: Copyright (c) 2023 UnderNET

package routes

import (
	"github.com/labstack/gommon/log"
	"github.com/undernetirc/cservice-api/controllers/admin"
	"github.com/undernetirc/cservice-api/middlewares"
)

func (r *RouteService) AdminRoleRoutes() {
	log.Info("Loading admin role routes")
	c := admin.NewAdminRoleController(r.service)
	router := r.routerGroup.Group("/admin/roles", middlewares.HasAuthorization(1000))
	router.GET("", c.GetRoles)
	router.POST("", c.CreateRole)
	router.PUT("/:id", c.UpdateRole)
	router.DELETE("/:id", c.DeleteRole)
	router.POST("/:id/users", c.AddUsersToRole)
	router.DELETE("/:id/users", c.RemoveUsersFromRole)
}
