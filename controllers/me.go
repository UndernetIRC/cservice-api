// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package controllers

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/jinzhu/copier"
	"github.com/labstack/echo/v4"

	"github.com/undernetirc/cservice-api/db/types/flags"
	"github.com/undernetirc/cservice-api/internal/helper"
	"github.com/undernetirc/cservice-api/models"
)

// MeController handles requests related to the current authenticated user
type MeController struct {
	s models.Querier
}

// NewMeController creates a new instance of MeController
func NewMeController(s models.Querier) *MeController {
	return &MeController{s: s}
}

// MeResponse represents the response structure for the current user
type MeResponse struct {
	ID           int32               `json:"id"                      extensions:"x-order=0"`
	Username     string              `json:"username"                extensions:"x-order=1"`
	Email        string              `json:"email,omitempty"         extensions:"x-order=2"`
	MaxLogins    int32               `json:"max_logins"              extensions:"x-order=3"`
	LanguageCode string              `json:"language_code,omitempty" extensions:"x-order=4"`
	LanguageName string              `json:"language_name,omitempty" extensions:"x-order=5"`
	LastSeen     int32               `json:"last_seen,omitempty"     extensions:"x-order=6"`
	TotpEnabled  bool                `json:"totp_enabled"            extensions:"x-order=8"`
	Channels     []MeChannelResponse `json:"channels,omitempty"      extensions:"x-order=9"`
}

// MeChannelResponse represents a channel associated with the current user
type MeChannelResponse struct {
	Name         string `json:"name"`
	ChannelID    int32  `json:"channel_id"`
	Access       int32  `json:"access"`
	LastModified int32  `json:"last_modified,omitempty"`
}

// GetMe returns detailed information about the current user
// @Summary Get current user information
// @Description Get current user information
// @Tags users
// @Accept json
// @Produce json
// @Success 200 {object} MeResponse
// @Failure 401 "Authorization information is missing or invalid."
// @Failure 404 "User not found."
// @Failure 500 "Internal server error."
// @Router /me [get]
// @Security JWTBearerToken
func (ctr *MeController) GetMe(c echo.Context) error {
	// Create a context with timeout for database operations
	ctx, cancel := context.WithTimeout(c.Request().Context(), 5*time.Second)
	defer cancel()

	// Get user claims from context
	claims := helper.GetClaimsFromContext(c)
	if claims == nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "Authorization information is missing or invalid")
	}

	// Fetch user data
	user, err := ctr.s.GetUserByID(ctx, claims.UserID)
	if err != nil {
		c.Logger().Errorf("Failed to fetch user by ID %d: %s", claims.UserID, err.Error())
		return echo.NewHTTPError(http.StatusNotFound, fmt.Sprintf("User with ID %d not found", claims.UserID))
	}

	// Create response and copy user data
	response := &MeResponse{}
	err = copier.Copy(&response, &user)
	if err != nil {
		c.Logger().Errorf("Failed to copy user to response DTO: %s", err.Error())
		return echo.NewHTTPError(http.StatusInternalServerError, "Internal server error")
	}

	// Set TOTP status
	response.TotpEnabled = user.Flags.HasFlag(flags.UserTotpEnabled)

	// Fetch user channels
	userChannels, err := ctr.s.GetUserChannels(ctx, claims.UserID)
	if err != nil {
		c.Logger().Errorf("Failed to fetch user channels: %s", err.Error())
		// Return partial response with empty channels instead of failing completely
		response.Channels = []MeChannelResponse{}
	} else {
		// Copy channel data to response
		err = copier.Copy(&response.Channels, &userChannels)
		if err != nil {
			c.Logger().Errorf("Failed to copy userChannels to response DTO: %s", err.Error())
			return echo.NewHTTPError(http.StatusInternalServerError, "Internal server error")
		}
	}

	return c.JSON(http.StatusOK, response)
}
