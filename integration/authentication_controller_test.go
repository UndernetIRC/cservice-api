//go:build integration

// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/undernetirc/cservice-api/controllers"
	"github.com/undernetirc/cservice-api/db/types/flags"
	"github.com/undernetirc/cservice-api/db/types/password"
	"github.com/undernetirc/cservice-api/internal/checks"
	"github.com/undernetirc/cservice-api/internal/config"
	"github.com/undernetirc/cservice-api/internal/helper"
	"github.com/undernetirc/cservice-api/models"
)

func TestAuthController_Login(t *testing.T) {
	config.DefaultConfig()

	service := models.NewService(db)
	checks.InitUser(context.Background(), db)

	authController := controllers.NewAuthenticationController(service, rdb, nil)

	e := echo.New()
	e.Validator = helper.NewValidator()
	e.POST("/", authController.Login)

	w := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"username": "Admin", "password":"temPass2020@"}`)
	r, _ := http.NewRequest("POST", "/", body)
	r.Header.Set("Content-Type", "application/json")

	e.ServeHTTP(w, r)

	resp := w.Result()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	loginResponse := new(controllers.LoginResponse)
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(loginResponse); err != nil {
		t.Error("error decoding", err)
	}

	assert.NotEmpty(t, loginResponse.AccessToken, "access token should not be empty")
}

func TestAuthController_LoginSuspendedUser(t *testing.T) {
	config.DefaultConfig()

	service := models.NewService(db)
	checks.InitUser(context.Background(), db)

	authController := controllers.NewAuthenticationController(service, rdb, nil)

	e := echo.New()
	e.Validator = helper.NewValidator()
	e.POST("/", authController.Login)

	pwd := password.Password("")
	require.NoError(t, pwd.Set("SuspendedPass1!"))

	nanoSuffix := fmt.Sprintf("%d", time.Now().UnixNano()%1000000)
	username := "susp" + nanoSuffix
	created, err := service.CreateUser(ctx, models.CreateUserParams{
		Username:         username,
		Password:         pwd,
		Email:            pgtype.Text{String: username + "@example.com", Valid: true},
		Flags:            flags.UserGlobalSuspend,
		LastUpdated:      int32(time.Now().Unix()),
		LastUpdatedBy:    pgtype.Text{String: "test", Valid: true},
		LanguageID:       pgtype.Int4{Int32: 1, Valid: true},
		QuestionID:       pgtype.Int2{Int16: 1, Valid: true},
		Verificationdata: pgtype.Text{String: "test_data", Valid: true},
		SignupTs:         pgtype.Int4{Int32: int32(time.Now().Unix()), Valid: true},
	})
	require.NoError(t, err)
	require.NotZero(t, created.ID)

	body := bytes.NewBufferString(fmt.Sprintf(
		`{"username": %q, "password": "SuspendedPass1!"}`, username,
	))
	w := httptest.NewRecorder()
	r, _ := http.NewRequest("POST", "/", body)
	r.Header.Set("Content-Type", "application/json")

	e.ServeHTTP(w, r)

	resp := w.Result()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Contains(t, w.Body.String(), "suspended")
	assert.Empty(t, w.Header().Get("Set-Cookie"))
}
