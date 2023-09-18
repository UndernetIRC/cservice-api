// SPDX-License-Identifier: MIT
// SPDX-FileCopyRightText: Copyright (c) 2023 UnderNET

package admin

import (
	"github.com/labstack/echo/v4"
	"github.com/undernetirc/cservice-api/internal/helper"
	"github.com/undernetirc/cservice-api/models"
	"net/http"
)

type RoleController struct {
	s models.Querier
}

func NewAdminRoleController(s models.Querier) *RoleController {
	return &RoleController{s: s}
}

type RoleListResponse struct {
	Roles []RoleNameResponse `json:"roles"`
}

type RoleNameResponse struct {
	ID          int32  `json:"id" extensions:"x-order=0"`
	Name        string `json:"name" extensions:"x-order=1"`
	Description string `json:"description" extensions:"x-order=2"`
}

func (ctr *RoleController) GetRoles(c echo.Context) error {
	roles, err := ctr.s.ListRoles(c.Request().Context())
	if err != nil {
		return err
	}

	response := &RoleListResponse{
		Roles: make([]RoleNameResponse, len(roles)),
	}

	for i, role := range roles {
		response.Roles[i] = RoleNameResponse{
			ID:          role.ID,
			Name:        role.Name,
			Description: role.Description,
		}
	}

	return c.JSON(http.StatusOK, response)
}

type RoleCreateRequest struct {
	Name        string `json:"name" validate:"required,min=3,max=50"`
	Description string `json:"description,max=255"`
}

type RoleCreateResponse struct {
	ID int32 `json:"id"`
}

func (ctr *RoleController) CreateRole(c echo.Context) error {
	currentUserName := helper.GetClaimsFromContext(c).Username

	var req RoleCreateRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, err)
	}
	if err := c.Validate(&req); err != nil {
		return c.JSON(http.StatusBadRequest, err)
	}

	role := new(models.CreateRoleParams)
	role.Name = req.Name
	role.Description = req.Description
	role.CreatedBy = currentUserName

	res, err := ctr.s.CreateRole(c.Request().Context(), *role)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, err)
	}

	return c.JSON(http.StatusCreated, RoleCreateResponse{ID: res.ID})
}
