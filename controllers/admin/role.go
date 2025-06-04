// SPDX-License-Identifier: MIT
// SPDX-FileCopyRightText: Copyright (c) 2023 UnderNET

// Package admin defines the admin controllers.
package admin

import (
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jinzhu/copier"

	"github.com/undernetirc/cservice-api/db"

	"github.com/labstack/echo/v4"
	apierrors "github.com/undernetirc/cservice-api/internal/errors"
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
	ID          int32  `json:"id"          extensions:"x-order=0"`
	Name        string `json:"name"        extensions:"x-order=1"`
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
	logger := helper.GetRequestLogger(c)
	roles, err := ctr.s.ListRoles(c.Request().Context())
	if err != nil {
		logger.Error("Failed to list roles",
			"error", err.Error())
		return apierrors.HandleDatabaseError(c, err)
	}

	response := &RoleListResponse{}
	err = copier.Copy(&response.Roles, &roles)
	if err != nil {
		logger.Error("Failed to copy roles to response DTO",
			"error", err.Error())
		return apierrors.HandleInternalError(c, err, "Failed to process roles")
	}

	return c.JSON(http.StatusOK, response)
}

// RoleDataRequest is a struct that holds the request for the create role endpoint
type RoleDataRequest struct {
	Name        string `json:"name"        validate:"required,min=3,max=50" extensions:"x-order=0"`
	Description string `json:"description" validate:"min=3,max=255"         extensions:"x-order=1"`
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
	logger := helper.GetRequestLogger(c)

	req := new(RoleDataRequest)
	if err := c.Bind(req); err != nil {
		return apierrors.HandleBadRequestError(c, "Invalid request format")
	}
	if err := c.Validate(req); err != nil {
		return apierrors.HandleValidationError(c, err)
	}

	claims := helper.GetClaimsFromContext(c)
	role := new(models.CreateRoleParams)
	err := copier.Copy(&role, &req)
	if err != nil {
		logger.Error("Failed to copy role request",
			"adminUser", claims.Username,
			"error", err.Error())
		return apierrors.HandleInternalError(c, err, "Failed to process role data")
	}

	role.CreatedBy = claims.Username

	res, err := ctr.s.CreateRole(c.Request().Context(), *role)
	if err != nil {
		if pgerr, ok := err.(*pgconn.PgError); ok {
			if pgerr.Code == "23505" {
				logger.Warn("Attempted to create duplicate role",
					"adminUser", claims.Username,
					"roleName", req.Name)
				return apierrors.HandleConflictError(c, "Role already exists")
			}
		}
		logger.Error("Failed to create role",
			"adminUser", claims.Username,
			"roleName", req.Name,
			"error", err.Error())
		return apierrors.HandleDatabaseError(c, err)
	}

	logger.Info("Role created successfully",
		"adminUser", claims.Username,
		"roleID", res.ID,
		"roleName", req.Name)

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
	logger := helper.GetRequestLogger(c)

	id, err := helper.SafeAtoi32(c.Param("id"))
	if err != nil {
		return apierrors.HandleBadRequestError(c, "Invalid role ID")
	}

	req := new(RoleDataRequest)
	if err := c.Bind(req); err != nil {
		return apierrors.HandleBadRequestError(c, "Invalid request format")
	}
	if err := c.Validate(req); err != nil {
		return apierrors.HandleValidationError(c, err)
	}

	claims := helper.GetClaimsFromContext(c)

	_, err = ctr.s.GetRoleByID(c.Request().Context(), id)
	if err != nil {
		logger.Warn("Attempted to update non-existent role",
			"adminUser", claims.Username,
			"roleID", id)
		return apierrors.HandleNotFoundError(c, "Role")
	}

	role := &models.UpdateRoleParams{ID: id}
	if err := copier.Copy(&role, &req); err != nil {
		logger.Error("Failed to copy role update request",
			"adminUser", claims.Username,
			"roleID", id,
			"error", err.Error())
		return apierrors.HandleInternalError(c, err, "Failed to process role data")
	}
	role.UpdatedBy = db.NewString(claims.Username)
	role.UpdatedAt = db.NewTimestamp(time.Now())

	err = ctr.s.UpdateRole(c.Request().Context(), *role)
	if err != nil {
		logger.Error("Failed to update role",
			"adminUser", claims.Username,
			"roleID", id,
			"error", err.Error())
		return apierrors.HandleDatabaseError(c, err)
	}

	logger.Info("Role updated successfully",
		"adminUser", claims.Username,
		"roleID", id,
		"roleName", req.Name)

	return c.JSON(http.StatusOK, roleUpdateResponse{ID: role.ID})
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
	logger := helper.GetRequestLogger(c)

	id, err := helper.SafeAtoi32(c.Param("id"))
	if err != nil {
		return apierrors.HandleBadRequestError(c, "Invalid role ID")
	}

	claims := helper.GetClaimsFromContext(c)

	err = ctr.s.DeleteRole(c.Request().Context(), id)
	if err != nil {
		logger.Warn("Failed to delete role",
			"adminUser", claims.Username,
			"roleID", id,
			"error", err.Error())
		return apierrors.HandleNotFoundError(c, "Role")
	}

	logger.Info("Role deleted successfully",
		"adminUser", claims.Username,
		"roleID", id)

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Role deleted successfully",
	})
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
	logger := helper.GetRequestLogger(c)

	roleID, err := helper.SafeAtoi32(c.Param("id"))
	if err != nil {
		return apierrors.HandleBadRequestError(c, "Invalid role ID")
	}

	req := new(UsersRequest)
	if err := c.Bind(req); err != nil {
		return apierrors.HandleBadRequestError(c, "Invalid request format")
	}
	if err := c.Validate(req); err != nil {
		return apierrors.HandleValidationError(c, err)
	}

	claims := helper.GetClaimsFromContext(c)

	users, err := ctr.s.GetUsersByUsernames(c.Request().Context(), req.Users)
	if err != nil {
		logger.Error("Failed to get users by usernames",
			"adminUser", claims.Username,
			"roleID", roleID,
			"error", err.Error())
		return apierrors.HandleDatabaseError(c, err)
	}

	var roleAssignments []models.AddUsersToRoleParams
	for _, user := range users {
		roleAssignments = append(roleAssignments, models.AddUsersToRoleParams{
			RoleID:    roleID,
			UserID:    user.ID,
			CreatedBy: claims.Username,
		})
	}

	res, err := ctr.s.AddUsersToRole(c.Request().Context(), roleAssignments)
	if err != nil {
		logger.Error("Failed to add users to role",
			"adminUser", claims.Username,
			"roleID", roleID,
			"error", err.Error())
		return apierrors.HandleDatabaseError(c, err)
	}

	logger.Info("Users added to role successfully",
		"adminUser", claims.Username,
		"roleID", roleID,
		"assignmentCount", res)

	return c.JSON(http.StatusOK, map[string]interface{}{
		"affected_rows": res,
	})
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
	logger := helper.GetRequestLogger(c)

	roleID, err := helper.SafeAtoi32(c.Param("id"))
	if err != nil {
		return apierrors.HandleBadRequestError(c, "Invalid role ID")
	}

	req := new(UsersRequest)
	if err := c.Bind(req); err != nil {
		return apierrors.HandleBadRequestError(c, "Invalid request format")
	}
	if err := c.Validate(req); err != nil {
		return apierrors.HandleValidationError(c, err)
	}

	claims := helper.GetClaimsFromContext(c)

	users, err := ctr.s.GetUsersByUsernames(c.Request().Context(), req.Users)
	if err != nil {
		logger.Error("Failed to get users by usernames for removal",
			"adminUser", claims.Username,
			"roleID", roleID,
			"error", err.Error())
		return apierrors.HandleDatabaseError(c, err)
	}

	var userIDs []int32
	for _, user := range users {
		userIDs = append(userIDs, user.ID)
	}

	err = ctr.s.RemoveUsersFromRole(c.Request().Context(), userIDs, roleID)
	if err != nil {
		logger.Error("Failed to remove users from role",
			"adminUser", claims.Username,
			"roleID", roleID,
			"error", err.Error())
		return apierrors.HandleDatabaseError(c, err)
	}

	logger.Info("Users removed from role successfully",
		"adminUser", claims.Username,
		"roleID", roleID)

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Users removed from role successfully",
	})
}
