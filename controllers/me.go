// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package controllers

import (
	"fmt"
	"net/http"

	"github.com/undernetirc/cservice-api/db/types/flags"

	"github.com/labstack/echo/v4"
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
	ID           int32               `json:"id" extensions:"x-order=0"`
	Username     string              `json:"username" extensions:"x-order=1"`
	Email        *string             `json:"email,omitempty" extensions:"x-order=2"`
	MaxLogins    *int32              `json:"max_logins" extensions:"x-order=3"`
	LanguageCode *string             `json:"language_code,omitempty" extensions:"x-order=4"`
	LanguageName *string             `json:"language_name,omitempty" extensions:"x-order=5"`
	LastSeen     *int32              `json:"last_seen,omitempty" extensions:"x-order=6"`
	TotpEnabled  bool                `json:"totp_enabled" extensions:"x-order=8"`
	Channels     []MeChannelResponse `json:"channels,omitempty" extensions:"x-order=9"`
}

type MeChannelResponse struct {
	Name         string `json:"name"`
	ChannelID    int32  `json:"channel_id"`
	Access       int32  `json:"access"`
	LastModified *int32 `json:"last_modified,omitempty"`
}

// GetMe godoc
// @Summary Get detailed information about the current user
// @Tags accounts
// @Accept json
// @Produce json
// @Success 200 {object} MeResponse
// @Failure 401 "Authorization information is missing or invalid."
// @Router /me [get]
func (ctr *MeController) GetMe(c echo.Context) error {
	claims := helper.GetClaimsFromContext(c)

	user, err := ctr.s.GetUserByID(c.Request().Context(), claims.UserId)
	if err != nil {
		return c.JSON(http.StatusNotFound, fmt.Sprintf("User by id %d not found", claims.UserId))
	}

	response := MeResponse{
		ID:           user.ID,
		Username:     user.UserName,
		Email:        user.Email,
		MaxLogins:    user.Maxlogins,
		LanguageCode: user.LanguageCode,
		LanguageName: user.LanguageName,
		LastSeen:     user.LastSeen,
		TotpEnabled:  user.Flags.HasFlag(flags.USER_TOTP_ENABLED),
	}

	userChannels, err := ctr.s.GetUserChannels(c.Request().Context(), claims.UserId)
	if err != nil {
		c.Logger().Errorf("Failed to fetch user channels: %s", err.Error())
	}

	for _, channel := range userChannels {
		response.Channels = append(response.Channels, MeChannelResponse{
			Name:         channel.Name,
			ChannelID:    channel.ChannelID,
			Access:       channel.Access,
			LastModified: channel.LastModif,
		})
	}

	return c.JSON(http.StatusOK, response)
}
