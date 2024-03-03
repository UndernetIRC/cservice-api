// SPDX-License-Identifier: MIT
// SPDX-FileCopyRightText: Copyright (c) 2023 UnderNET

// Package admin defines the admin controllers.
package admin

import (
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jinzhu/copier"

	"github.com/undernetirc/cservice-api/db"

	"github.com/labstack/echo/v4"
	"github.com/undernetirc/cservice-api/internal/helper"
	"github.com/undernetirc/cservice-api/models"
)

// RoleController is a struct that holds the service
type RoleController struct {
	s models.Querier
}

// NewAdminRoleController creates a new RoleController
func NewAdminRoleController(s models.Querier) *RoleController {
	return &RoleController{s: s}
}

// RoleListResponse is a struct that holds the response for the list roles endpoint
type RoleListResponse struct {
	Roles []RoleNameResponse `json:"roles,omitempty"`
}

// RoleNameResponse is a struct that holds the response for the role name endpoint
type RoleNameResponse struct {
	ID          int32  `json:"id" extensions:"x-order=0"`
	Name        string `json:"name" extensions:"x-order=1"`
	Description string `json:"description" extensions:"x-order=2"`
}

// GetRoles returns a list of roles
// @Summary List roles
// @Description Returns a list of roles
// @Tags admin
// @Produce json
// @Success 200 {object} RoleListResponse
// @Router /admin/roles [get]
// @Security JWTBearerToken
func (ctr *RoleController) GetRoles(c echo.Context) error {
	roles, err := ctr.s.ListRoles(c.Request().Context())
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	response := &RoleListResponse{}
	err = copier.Copy(&response.Roles, &roles)
	if err != nil {
		c.Logger().Errorf("Failed to copy roles to response DTO: %s", err.Error())
		return echo.NewHTTPError(http.StatusInternalServerError, "Internal server error")
	}

	return c.JSON(http.StatusOK, response)
}

// RoleDataRequest is a struct that holds the request for the create role endpoint
type RoleDataRequest struct {
	Name        string `json:"name" validate:"required,min=3,max=50" extensions:"x-order=0"`
	Description string `json:"description" validate:"min=3,max=255" extensions:"x-order=1"`
}

// RoleCreateResponse is a struct that holds the response for the create role endpoint
type RoleCreateResponse struct {
	ID int32 `json:"id"`
}

// CreateRole creates a new role
// @Summary Create role
// @Description Creates a new role
// @Tags admin
// @Accept json
// @Produce json
// @Param data body RoleDataRequest true "Role data"
// @Success 201 {object} RoleCreateResponse
// @Router /admin/roles [post]
// @Security JWTBearerToken
func (ctr *RoleController) CreateRole(c echo.Context) error {
	req := new(RoleDataRequest)
	if err := c.Bind(req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	if err := c.Validate(req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	role := new(models.CreateRoleParams)
	err := copier.Copy(&role, &req)
	if err != nil {
		c.Logger().Errorf("Failed to copy role to response DTO: %s", err.Error())
		return echo.NewHTTPError(http.StatusInternalServerError, "Internal server error")
	}

	role.CreatedBy = helper.GetClaimsFromContext(c).Username

	res, err := ctr.s.CreateRole(c.Request().Context(), *role)
	if err != nil {
		if pgerr, ok := err.(*pgconn.PgError); ok {
			if pgerr.Code == "23505" {
				return echo.NewHTTPError(http.StatusUnprocessableEntity, "role already exists")
			}
		}
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	return c.JSON(http.StatusCreated, RoleCreateResponse{ID: res.ID})
}

// roleUpdateResponse is a struct that holds the response for the update role endpoint
type roleUpdateResponse struct {
	ID int32 `json:"id"`
}

// UpdateRole updates a role
// @Summary Update role
// @Description Updates a role
// @Tags admin
// @Accept json
// @Produce json
// @Param id path int true "Role ID"
// @Param data body RoleDataRequest true "Role data"
// @Success 200 {object} roleUpdateResponse
// @Router /admin/roles/{id} [put]
// @Security JWTBearerToken
func (ctr *RoleController) UpdateRole(c echo.Context) error {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	req := new(RoleDataRequest)
	if err := c.Bind(req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	if err := c.Validate(req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	_, err = ctr.s.GetRoleByID(c.Request().Context(), int32(id))
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, err.Error())
	}

	role := &models.UpdateRoleParams{ID: int32(id)}
	if err := copier.Copy(&role, &req); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	role.UpdatedBy = db.NewString(helper.GetClaimsFromContext(c).Username)
	role.UpdatedAt = db.NewTimestamp(time.Now())

	err = ctr.s.UpdateRole(c.Request().Context(), *role)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	return c.JSON(http.StatusOK, &roleUpdateResponse{ID: role.ID})
}

// DeleteRole deletes a role
// @Summary Delete role
// @Description Deletes a role
// @Tags admin
// @Param id path int true "Role ID"
// @Success 200
// @Router /admin/roles/{id} [delete]
// @Security JWTBearerToken
func (ctr *RoleController) DeleteRole(c echo.Context) error {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	err = ctr.s.DeleteRole(c.Request().Context(), int32(id))
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, err.Error())
	}
	return c.JSON(http.StatusOK, nil)
}

// UsersRequest is a struct that holds the request for the assign users to role endpoint
type UsersRequest struct {
	Users []string `json:"users" validate:"required"`
}

// AddUsersToRole adds a role to a user
// @Summary Assign users to role
// @Description Assigns users to a role
// @Tags admin
// @Accept json
// @Produce json
// @Param id path int true "Role ID"
// @Param data body UsersRequest true "List of usernames"
// @Success 200
// @Router /admin/roles/{id}/users [post]
// @Security JWTBearerToken
func (ctr *RoleController) AddUsersToRole(c echo.Context) error {
	roleID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	req := new(UsersRequest)
	if err := c.Bind(req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	if err := c.Validate(req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	users, err := ctr.s.GetUsersByUsernames(c.Request().Context(), req.Users)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	var roleAssignments []models.AddUsersToRoleParams

	for _, user := range users {
		roleAssignments = append(roleAssignments, models.AddUsersToRoleParams{
			RoleID:    int32(roleID),
			UserID:    user.ID,
			CreatedBy: helper.GetClaimsFromContext(c).Username,
		})
	}
	res, err := ctr.s.AddUsersToRole(c.Request().Context(), roleAssignments)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	return c.JSON(http.StatusOK, res)
}

// RemoveUsersFromRole removes a role from a user
// @Summary Remove users from role
// @Description Removes users from a role
// @Tags admin
// @Accept json
// @Produce json
// @Param id path int true "Role ID"
// @Param data body UsersRequest true "List of usernames"
// @Success 200
// @Router /admin/roles/{id}/users [delete]
// @Security JWTBearerToken
func (ctr *RoleController) RemoveUsersFromRole(c echo.Context) error {
	roleID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	req := new(UsersRequest)
	if err := c.Bind(req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	if err := c.Validate(req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	users, err := ctr.s.GetUsersByUsernames(c.Request().Context(), req.Users)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	var userIds []int32
	for _, user := range users {
		userIds = append(userIds, user.ID)
	}

	err = ctr.s.RemoveUsersFromRole(c.Request().Context(), userIds, int32(roleID))
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	return c.JSON(http.StatusOK, nil)
}
