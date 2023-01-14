//go:build integration

// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package integration

import (
	"encoding/json"
	"github.com/labstack/echo/v4"
	"github.com/undernetirc/cservice-api/controllers"
	"github.com/undernetirc/cservice-api/models"
	"gopkg.in/go-playground/assert.v1"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetUserAPI(t *testing.T) {
	service := models.NewService(db)
	userController := controllers.NewUserController(service)

	e := echo.New()
	e.GET("/users/:id", userController.GetUser)

	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "/users/1", nil)

	e.ServeHTTP(w, r)
	resp := w.Result()

	userResponse := new(controllers.UserResponse)
	dec := json.NewDecoder(resp.Body)
	err := dec.Decode(userResponse)
	if err != nil {
		t.Error("error decoding", err)
	}

	assert.Equal(t, resp.StatusCode, http.StatusOK)
	assert.Equal(t, userResponse.Username, "Admin")
	assert.Equal(t, userResponse.Channels[0].Name, "*")
	assert.Equal(t, userResponse.Channels[1].Name, "#coder-com")

}

func TestGetNonExistingUserID(t *testing.T) {
	service := models.NewService(db)
	userController := controllers.NewUserController(service)

	e := echo.New()
	e.GET("/users/:id", userController.GetUser)

	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "/users/2", nil)

	e.ServeHTTP(w, r)
	resp := w.Result()

	assert.Equal(t, resp.StatusCode, http.StatusNotFound)
}
