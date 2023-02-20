// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package controllers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/undernetirc/cservice-api/db/types/flags"

	"github.com/golang-jwt/jwt/v4"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/undernetirc/cservice-api/internal/config"
	"github.com/undernetirc/cservice-api/internal/helper"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/undernetirc/cservice-api/db/mocks"
	"github.com/undernetirc/cservice-api/models"
)

func TestGetMe(t *testing.T) {
	config.Conf = &config.Config{}
	config.Conf.JWT.SigningMethod = "HS256"
	config.Conf.JWT.SigningKey = "hirkumpirkum"
	config.Conf.JWT.RefreshSigningKey = "hirkumpirkum"
	config.Conf.Redis.EnableMultiLogout = true

	jwtConfig := echojwt.Config{
		SigningMethod: config.Conf.JWT.SigningMethod,
		SigningKey:    config.Conf.GetJWTPublicKey(),
		NewClaimsFunc: func(c echo.Context) jwt.Claims {
			return new(helper.JwtClaims)
		},
	}

	claims := new(helper.JwtClaims)
	claims.UserId = 1
	claims.Username = "Admin"
	tokens, _ := helper.GenerateToken(claims, time.Now())

	t.Run("Test GetMe with valid token", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		newUser := models.GetUserByIDRow{ID: 1, UserName: "Admin", Flags: flags.UserTotpEnabled}

		db.On("GetUserByID", mock.Anything, int32(1)).
			Return(newUser, nil).
			Once()
		db.On("GetUserChannels", mock.Anything, int32(1)).
			Return([]models.GetUserChannelsRow{
				{ChannelID: 1, Name: "*"},
				{ChannelID: 2, Name: "#coder-com"}}, nil).
			Once()

		controller := NewMeController(db)

		e := echo.New()
		e.Use(echojwt.WithConfig(jwtConfig))
		e.GET("/me", controller.GetMe)

		w := httptest.NewRecorder()
		r, _ := http.NewRequest("GET", "/me", nil)
		r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokens.AccessToken))

		e.ServeHTTP(w, r)
		resp := w.Result()

		meResponse := new(MeResponse)
		dec := json.NewDecoder(resp.Body)
		err := dec.Decode(meResponse)
		if err != nil {
			t.Error("error decoding", err)
		}

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "Admin", meResponse.Username)
		assert.Equal(t, "*", meResponse.Channels[0].Name)
		assert.Equal(t, "#coder-com", meResponse.Channels[1].Name)
		assert.True(t, meResponse.TotpEnabled)
	})
}
