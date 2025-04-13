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

type MeController struct {
	s models.Querier
}

func NewMeController(s models.Querier) *MeController {
	return &MeController{s: s}
}

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
// @Router /me [get]
// @Security JWTBearerToken
func (ctr *MeController) GetMe(c echo.Context) error {
	claims := helper.GetClaimsFromContext(c)

	user, err := ctr.s.GetUserByID(c.Request().Context(), claims.UserID)
	if err != nil {
		return c.JSON(http.StatusNotFound, fmt.Sprintf("User by id %d not found", claims.UserID))
	}

	response := &MeResponse{}
	err = copier.Copy(&response, &user)
	if err != nil {
		c.Logger().Errorf("Failed to copy user to response DTO: %s", err.Error())
		return echo.NewHTTPError(http.StatusInternalServerError, "Internal server error")
	}
	response.TotpEnabled = user.Flags.HasFlag(flags.UserTotpEnabled)
	userChannels, err := ctr.s.GetUserChannels(c.Request().Context(), claims.UserID)
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
