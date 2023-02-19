// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package controllers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/undernetirc/cservice-api/db/types/flags"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/undernetirc/cservice-api/db/mocks"
	"github.com/undernetirc/cservice-api/models"
)

func TestGetUser(t *testing.T) {
	db := mocks.NewQuerier(t)
	db.On("GetUserByID", mock.Anything, int32(1)).
		Return(models.GetUserByIDRow{ID: 1, UserName: "Admin", Flags: flags.UserTotpEnabled}, nil).
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
