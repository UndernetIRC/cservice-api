// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package controllers

import (
	"fmt"
	"net/http"

	"github.com/jinzhu/copier"
	"github.com/labstack/echo/v4"

	"github.com/undernetirc/cservice-api/db/types/flags"
	"github.com/undernetirc/cservice-api/internal/helper"
	"github.com/undernetirc/cservice-api/models"
)

type UserController struct {
	s models.Querier
}

func NewUserController(s models.Querier) *UserController {
	return &UserController{s: s}
}

type UserResponse struct {
	ID           int32                 `json:"id"                      extensions:"x-order=0"`
	Username     string                `json:"username"                extensions:"x-order=1"`
	Email        string                `json:"email,omitempty"         extensions:"x-order=2"`
	MaxLogins    int32                 `json:"max_logins"              extensions:"x-order=3"`
	LanguageCode string                `json:"language_code,omitempty" extensions:"x-order=4"`
	LanguageName string                `json:"language_name,omitempty" extensions:"x-order=5"`
	LastSeen     int32                 `json:"last_seen,omitempty"     extensions:"x-order=6"`
	TotpEnabled  bool                  `json:"totp_enabled"            extensions:"x-order=7"`
	Channels     []UserChannelResponse `json:"channels,omitempty"      extensions:"x-order=8"`
}

type UserChannelResponse struct {
	Name         string `json:"name"`
	ChannelID    int32  `json:"channel_id"`
	Access       int32  `json:"access"`
	LastModified int32  `json:"last_modified,omitempty"`
}

// GetUser returns a user by id
// @Summary Get user data by id
// @Description Returns a user by id
// @Tags users
// @Produce json
// @Param id path int true "User ID"
// @Success 200 {object} UserResponse
// @Router /users/{id} [get]
// @Security JWTBearerToken
func (ctr *UserController) GetUser(c echo.Context) error {
	id, err := helper.SafeAtoi32(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid user ID")
	}

	user, err := ctr.s.GetUser(c.Request().Context(), models.GetUserParams{
		ID: id,
	})
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, fmt.Sprintf("User by id %d not found", id))
	}

	response := &UserResponse{}
	err = copier.Copy(&response, &user)
	if err != nil {
		c.Logger().Errorf("Failed to copy user to response DTO: %s", err.Error())
		return echo.NewHTTPError(http.StatusInternalServerError, "Internal server error")
	}
	response.TotpEnabled = user.Flags.HasFlag(flags.UserTotpEnabled)

	userChannels, err := ctr.s.GetUserChannels(c.Request().Context(), id)
	if err != nil {
		c.Logger().Errorf("Failed to fetch user channels: %s", err.Error())
	}

	err = copier.Copy(&response.Channels, &userChannels)
	if err != nil {
		c.Logger().Errorf("Failed to copy userChannels to response DTO: %s", err.Error())
		return echo.NewHTTPError(http.StatusInternalServerError, "Internal server error")
	}

	return c.JSON(http.StatusOK, response)
}

type UserRolesResponse struct {
	User struct {
		ID       int32  `json:"id" extensions:"x-order=0"`
		Username string `json:"username" extensions:"x-order=1"`
		Roles    []Role `json:"roles" extensions:"x-order=1"`
	} `json:"user" extensions:"x-order=0"`
}

type Role struct {
	ID          int32  `json:"id"          extensions:"x-order=0"`
	Name        string `json:"name"        extensions:"x-order=1"`
	Description string `json:"description" extensions:"x-order=2"`
}

// GetUserRoles returns the roles for a given user
// @Summary Get the roles for a given user
// @Description Get the roles for a given user
// @Tags users
// @Produce json
// @Param id path int true "User ID"
// @Success 200 {object} UserRolesResponse
// @Failure 400 {string} string "Invalid user ID"
// @Failure 404 {string} string "User not found"
// @Failure 500 {string} string "Internal server error"
// @Router /users/{id}/roles [get]
// @Security JWTBearerToken
func (ctr *UserController) GetUserRoles(c echo.Context) error {
	id, err := helper.SafeAtoi32(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid user ID")
	}

	user, err := ctr.s.GetUserByID(c.Request().Context(), id)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	roles, err := ctr.s.ListUserRoles(c.Request().Context(), id)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	resp := new(UserRolesResponse)
	resp.User.ID = user.ID
	resp.User.Username = user.Username
	for _, role := range roles {
		resp.User.Roles = append(resp.User.Roles, Role{
			ID:          role.ID,
			Name:        role.Name,
			Description: role.Description,
		})
	}

	return c.JSON(http.StatusOK, resp)
}

func (ctr *UserController) GetUserChannels(c echo.Context) error {
	id, err := helper.SafeAtoi32(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid user ID")
	}

	userChannels, err := ctr.s.GetUserChannels(c.Request().Context(), id)
	if err != nil {
		c.Logger().Errorf("Failed to fetch user channels: %s", err.Error())
		return echo.NewHTTPError(http.StatusInternalServerError, "Internal server error")
	}

	return c.JSON(http.StatusOK, userChannels)
}
