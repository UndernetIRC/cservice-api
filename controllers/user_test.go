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

	"github.com/golang-jwt/jwt/v5"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/undernetirc/cservice-api/internal/config"
	"github.com/undernetirc/cservice-api/internal/helper"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/undernetirc/cservice-api/db/mocks"
	"github.com/undernetirc/cservice-api/models"
)

func TestGetUser(t *testing.T) {
	db := mocks.NewQuerier(t)
	db.On("GetUser", mock.Anything, models.GetUserParams{ID: int32(1)}).
		Return(models.GetUserRow{ID: 1, Username: "Admin", Flags: flags.UserTotpEnabled}, nil).
		Once()
	db.On("GetUserChannels", mock.Anything, int32(1)).
		Return([]models.GetUserChannelsRow{
			{ChannelID: 1, Name: "*"},
			{ChannelID: 2, Name: "#coder-com"}}, nil).
		Once()

	userController := NewUserController(db)
	e := echo.New()
	e.GET("/users/:id", userController.GetUser)

	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "/users/1", nil)

	e.ServeHTTP(w, r)
	resp := w.Result()

	userResponse := new(UserResponse)
	dec := json.NewDecoder(resp.Body)
	err := dec.Decode(userResponse)
	if err != nil {
		t.Error("error decoding", err)
	}

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "Admin", userResponse.Username)
	assert.Equal(t, "*", userResponse.Channels[0].Name)
	assert.Equal(t, "#coder-com", userResponse.Channels[1].Name)
	assert.True(t, userResponse.TotpEnabled)
}

func TestGetCurrentUser(t *testing.T) {
	config.DefaultConfig()

	jwtConfig := echojwt.Config{
		SigningMethod: config.ServiceJWTSigningMethod.GetString(),
		SigningKey:    helper.GetJWTPublicKey(),
		NewClaimsFunc: func(_ echo.Context) jwt.Claims {
			return new(helper.JwtClaims)
		},
	}

	claims := new(helper.JwtClaims)
	claims.UserID = 1
	claims.Username = "Admin"
	tokens, _ := helper.GenerateToken(claims, time.Now())

	t.Run("Test GetCurrentUser with valid token", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		newUser := models.GetUserByIDRow{ID: 1, Username: "Admin", Flags: flags.UserTotpEnabled}

		db.On("GetUserByID", mock.Anything, int32(1)).
			Return(newUser, nil).
			Once()
		db.On("GetUserChannels", mock.Anything, int32(1)).
			Return([]models.GetUserChannelsRow{
				{ChannelID: 1, Name: "*"},
				{ChannelID: 2, Name: "#coder-com"}}, nil).
			Once()

		controller := NewUserController(db)

		e := echo.New()
		e.Use(echojwt.WithConfig(jwtConfig))
		e.GET("/user", controller.GetCurrentUser)

		w := httptest.NewRecorder()
		r, _ := http.NewRequest("GET", "/user", nil)
		r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokens.AccessToken))

		e.ServeHTTP(w, r)
		resp := w.Result()

		userResponse := new(UserResponse)
		dec := json.NewDecoder(resp.Body)
		err := dec.Decode(userResponse)
		if err != nil {
			t.Error("error decoding", err)
		}

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "Admin", userResponse.Username)
		assert.Equal(t, "*", userResponse.Channels[0].Name)
		assert.Equal(t, "#coder-com", userResponse.Channels[1].Name)
		assert.True(t, userResponse.TotpEnabled)
	})
}
