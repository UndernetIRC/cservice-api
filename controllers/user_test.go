// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package controllers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestChangePassword(t *testing.T) {
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

	t.Run("Successful password change", func(t *testing.T) {
		db := mocks.NewQuerier(t)

		// Mock user with existing password
		existingUser := models.User{
			ID:       1,
			Username: "Admin",
			Password: "oldHashedPassword",
		}

		// Set up the password to validate correctly
		_ = existingUser.Password.Set("currentPassword123")

		db.On("GetUserByUsername", mock.Anything, "Admin").
			Return(existingUser, nil).
			Once()
		db.On("UpdateUserPassword", mock.Anything, mock.AnythingOfType("models.UpdateUserPasswordParams")).
			Return(nil).
			Once()

		controller := NewUserController(db)

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.Use(echojwt.WithConfig(jwtConfig))
		e.PUT("/user/password", controller.ChangePassword)

		requestBody := `{
			"current_password": "currentPassword123",
			"new_password": "newPassword123!",
			"confirm_password": "newPassword123!"
		}`

		w := httptest.NewRecorder()
		r, _ := http.NewRequest("PUT", "/user/password", strings.NewReader(requestBody))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokens.AccessToken))

		e.ServeHTTP(w, r)
		resp := w.Result()

		var response map[string]string
		dec := json.NewDecoder(resp.Body)
		err := dec.Decode(&response)
		if err != nil {
			t.Error("error decoding", err)
		}

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "Password changed successfully", response["message"])
	})

	t.Run("Invalid current password", func(t *testing.T) {
		db := mocks.NewQuerier(t)

		// Mock user with existing password
		existingUser := models.User{
			ID:       1,
			Username: "Admin",
			Password: "oldHashedPassword",
		}

		// Set up a different password so validation fails
		_ = existingUser.Password.Set("differentPassword123")

		db.On("GetUserByUsername", mock.Anything, "Admin").
			Return(existingUser, nil).
			Once()

		controller := NewUserController(db)

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.Use(echojwt.WithConfig(jwtConfig))
		e.PUT("/user/password", controller.ChangePassword)

		requestBody := `{
			"current_password": "wrongPassword123",
			"new_password": "newPassword123!",
			"confirm_password": "newPassword123!"
		}`

		w := httptest.NewRecorder()
		r, _ := http.NewRequest("PUT", "/user/password", strings.NewReader(requestBody))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokens.AccessToken))

		e.ServeHTTP(w, r)
		resp := w.Result()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("Password validation errors", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		controller := NewUserController(db)

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.Use(echojwt.WithConfig(jwtConfig))
		e.PUT("/user/password", controller.ChangePassword)

		testCases := []struct {
			name         string
			requestBody  string
			expectedCode int
		}{
			{
				name:         "Missing current password",
				requestBody:  `{"new_password": "newPassword123!", "confirm_password": "newPassword123!"}`,
				expectedCode: http.StatusBadRequest,
			},
			{
				name:         "New password too short",
				requestBody:  `{"current_password": "current123", "new_password": "short", "confirm_password": "short"}`,
				expectedCode: http.StatusBadRequest,
			},
			{
				name:         "Passwords don't match",
				requestBody:  `{"current_password": "current123", "new_password": "newPassword123!", "confirm_password": "different123!"}`,
				expectedCode: http.StatusBadRequest,
			},
			{
				name:         "New password too long",
				requestBody:  `{"current_password": "current123", "new_password": "` + strings.Repeat("a", 73) + `", "confirm_password": "` + strings.Repeat("a", 73) + `"}`,
				expectedCode: http.StatusBadRequest,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				w := httptest.NewRecorder()
				r, _ := http.NewRequest("PUT", "/user/password", strings.NewReader(tc.requestBody))
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokens.AccessToken))

				e.ServeHTTP(w, r)
				resp := w.Result()

				assert.Equal(t, tc.expectedCode, resp.StatusCode)
			})
		}
	})

	t.Run("User not found", func(t *testing.T) {
		db := mocks.NewQuerier(t)

		db.On("GetUserByUsername", mock.Anything, "Admin").
			Return(models.User{}, fmt.Errorf("user not found")).
			Once()

		controller := NewUserController(db)

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.Use(echojwt.WithConfig(jwtConfig))
		e.PUT("/user/password", controller.ChangePassword)

		requestBody := `{
			"current_password": "currentPassword123",
			"new_password": "newPassword123!",
			"confirm_password": "newPassword123!"
		}`

		w := httptest.NewRecorder()
		r, _ := http.NewRequest("PUT", "/user/password", strings.NewReader(requestBody))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokens.AccessToken))

		e.ServeHTTP(w, r)
		resp := w.Result()

		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("Database update error", func(t *testing.T) {
		db := mocks.NewQuerier(t)

		// Mock user with existing password
		existingUser := models.User{
			ID:       1,
			Username: "Admin",
			Password: "oldHashedPassword",
		}

		// Set up the password to validate correctly
		_ = existingUser.Password.Set("currentPassword123")

		db.On("GetUserByUsername", mock.Anything, "Admin").
			Return(existingUser, nil).
			Once()
		db.On("UpdateUserPassword", mock.Anything, mock.AnythingOfType("models.UpdateUserPasswordParams")).
			Return(fmt.Errorf("database error")).
			Once()

		controller := NewUserController(db)

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.Use(echojwt.WithConfig(jwtConfig))
		e.PUT("/user/password", controller.ChangePassword)

		requestBody := `{
			"current_password": "currentPassword123",
			"new_password": "newPassword123!",
			"confirm_password": "newPassword123!"
		}`

		w := httptest.NewRecorder()
		r, _ := http.NewRequest("PUT", "/user/password", strings.NewReader(requestBody))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokens.AccessToken))

		e.ServeHTTP(w, r)
		resp := w.Result()

		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})

	t.Run("Missing JWT token", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		controller := NewUserController(db)

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.Use(echojwt.WithConfig(jwtConfig))
		e.PUT("/user/password", controller.ChangePassword)

		requestBody := `{
			"current_password": "currentPassword123",
			"new_password": "newPassword123!",
			"confirm_password": "newPassword123!"
		}`

		w := httptest.NewRecorder()
		r, _ := http.NewRequest("PUT", "/user/password", strings.NewReader(requestBody))
		r.Header.Set("Content-Type", "application/json")
		// No Authorization header

		e.ServeHTTP(w, r)
		resp := w.Result()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode) // JWT middleware returns 400 for missing token
	})

	t.Run("Invalid JSON request", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		controller := NewUserController(db)

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.Use(echojwt.WithConfig(jwtConfig))
		e.PUT("/user/password", controller.ChangePassword)

		requestBody := `{"invalid": json}`

		w := httptest.NewRecorder()
		r, _ := http.NewRequest("PUT", "/user/password", strings.NewReader(requestBody))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokens.AccessToken))

		e.ServeHTTP(w, r)
		resp := w.Result()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
}
