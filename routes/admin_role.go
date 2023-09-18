// SPDX-License-Identifier: MIT
// SPDX-FileCopyRightText: Copyright (c) 2023 UnderNET

package routes

import (
	"github.com/labstack/gommon/log"
	"github.com/undernetirc/cservice-api/controllers/admin"
)

func (r *RouteService) AdminRoleRoutes() {
	log.Info("Loading admin role routes")
	c := admin.NewAdminRoleController(r.service)
	router := r.routerGroup.Group("/admin/roles")
	router.GET("", c.GetRoles)
}
