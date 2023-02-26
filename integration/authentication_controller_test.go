//go:build integration

// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/undernetirc/cservice-api/controllers"
	"github.com/undernetirc/cservice-api/internal/config"
	"github.com/undernetirc/cservice-api/internal/helper"
	"github.com/undernetirc/cservice-api/models"

	"github.com/labstack/echo/v4"
)

func TestAuthController_Login(t *testing.T) {
	config.Conf = &config.Config{}
	config.Conf.JWT.SigningMethod = "HS256"
	config.Conf.JWT.SigningKey = "hirkumpirkum"
	config.Conf.JWT.RefreshSigningKey = "hirkumpirkum"
	/*
		jwtConfig := echojwt.Config{
			SigningMethod: config.Conf.JWT.SigningMethod,
			SigningKey:    config.Conf.GetJWTPublicKey(),
			NewClaimsFunc: func(c echo.Context) jwt.Claims {
				return new(helper.JwtClaims)
			},
		}
	*/
	service := models.NewService(db)
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
