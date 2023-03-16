// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package controllers

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/undernetirc/cservice-api/db/types/flags"

	"github.com/labstack/echo/v4"
	"github.com/undernetirc/cservice-api/models"
)

type UserController struct {
	s models.Querier
}

func NewUserController(s models.Querier) *UserController {
	return &UserController{s: s}
}

type UserResponse struct {
	ID           int32                 `json:"id" extensions:"x-order=0"`
	Username     string                `json:"username" extensions:"x-order=1"`
	Email        string                `json:"email,omitempty" extensions:"x-order=2"`
	MaxLogins    int32                 `json:"max_logins" extensions:"x-order=3"`
	LanguageCode string                `json:"language_code,omitempty" extensions:"x-order=4"`
	LanguageName string                `json:"language_name,omitempty" extensions:"x-order=5"`
	LastSeen     int32                 `json:"last_seen,omitempty" extensions:"x-order=6"`
	TotpEnabled  bool                  `json:"totp_enabled" extensions:"x-order=7"`
	Channels     []UserChannelResponse `json:"channels,omitempty" extensions:"x-order=8"`
}

type UserChannelResponse struct {
	Name         string `json:"name"`
	ChannelID    int32  `json:"channel_id"`
	Access       int32  `json:"access"`
	LastModified int32  `json:"last_modified,omitempty"`
}

func (ctr *UserController) GetUser(c echo.Context) error {
	id, _ := strconv.Atoi(c.Param("id"))
	user, err := ctr.s.GetUserByID(c.Request().Context(), int32(id))
	if err != nil {
		return c.JSONPretty(http.StatusNotFound, fmt.Sprintf("User by id %d not found", id), " ")
	}

	response := &UserResponse{
		ID:           user.ID,
		Username:     user.UserName,
		Email:        user.Email.String,
		MaxLogins:    user.Maxlogins.Int32,
		LanguageCode: user.LanguageCode.String,
		LanguageName: user.LanguageName.String,
		LastSeen:     user.LastSeen.Int32,
		TotpEnabled:  user.Flags.HasFlag(flags.UserTotpEnabled),
	}

	userChannels, err := ctr.s.GetUserChannels(c.Request().Context(), int32(id))
	if err != nil {
		c.Logger().Errorf("Failed to fetch user channels: %s", err.Error())
	}

	for _, channel := range userChannels {
		response.Channels = append(response.Channels, UserChannelResponse{
			Name:         channel.Name,
			ChannelID:    channel.ChannelID,
			Access:       channel.Access,
			LastModified: channel.LastModif.Int32,
		})
	}

	return c.JSON(http.StatusOK, response)
}
