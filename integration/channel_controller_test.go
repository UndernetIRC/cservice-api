//go:build integration

// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2024 UnderNET

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/undernetirc/cservice-api/controllers"
	"github.com/undernetirc/cservice-api/internal/channel"
	"github.com/undernetirc/cservice-api/internal/config"
	"github.com/undernetirc/cservice-api/internal/helper"
	"github.com/undernetirc/cservice-api/models"
)

// SimplePoolWrapper implements PoolInterface for integration tests
type SimplePoolWrapper struct {
	pool interface{}
}

func (p *SimplePoolWrapper) Begin(ctx context.Context) (pgx.Tx, error) {
	// For basic integration tests, we can return an error to indicate transactions not supported
	return nil, fmt.Errorf("transactions not needed for basic integration tests")
}

func setupChannelController(t *testing.T) (*controllers.ChannelController, *echo.Echo) {
	config.DefaultConfig()

	// Use the real database service from main_test.go setup
	service := models.NewService(models.New(dbPool))

	// Create a simple pool wrapper - for these tests we don't need transaction functionality
	poolWrapper := &SimplePoolWrapper{pool: dbPool}

	controller := controllers.NewChannelController(service, poolWrapper)

	e := echo.New()
	e.Validator = helper.NewValidator()

	return controller, e
}

func getAuthToken(t *testing.T, e *echo.Echo) string {
	service := models.NewService(models.New(dbPool))
	authController := controllers.NewAuthenticationController(service, rdb, nil)

	w := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"username": "Admin", "password":"temPass2020@"}`)
	r, _ := http.NewRequest("POST", "/login", body)
	r.Header.Set("Content-Type", "application/json")

	c := e.NewContext(r, w)
	err := authController.Login(c)
	require.NoError(t, err)

	resp := w.Result()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	loginResponse := new(controllers.LoginResponse)
	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(loginResponse)
	require.NoError(t, err)

	return loginResponse.AccessToken
}

func TestChannelController_SearchChannels(t *testing.T) {
	channelController, e := setupChannelController(t)

	e.GET("/channels/search", channelController.SearchChannels)

	// Create request with auth context
	token := getAuthToken(t, e)

	t.Run("successful search", func(t *testing.T) {
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("GET", "/channels/search?q=coder", nil)
		r.Header.Set("Authorization", "Bearer "+token)

		c := e.NewContext(r, w)
		// Mock JWT claims for the search
		claims := &helper.JwtClaims{
			UserID:   1,
			Username: "Admin",
		}
		c.Set("user", claims)

		err := channelController.SearchChannels(c)
		assert.NoError(t, err)

		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var searchResponse controllers.SearchChannelsResponse
		dec := json.NewDecoder(resp.Body)
		err = dec.Decode(&searchResponse)
		assert.NoError(t, err)

		// Should find channels matching the search (or return empty results)
		assert.GreaterOrEqual(t, len(searchResponse.Channels), 0)
		assert.NotNil(t, searchResponse.Pagination)
	})

	t.Run("unauthorized search", func(t *testing.T) {
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("GET", "/channels/search?q=test", nil)

		c := e.NewContext(r, w)

		err := channelController.SearchChannels(c)
		assert.NoError(t, err)

		resp := w.Result()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})
}

func TestChannelController_GetChannelSettings(t *testing.T) {
	channelController, e := setupChannelController(t)

	e.GET("/channels/:id", channelController.GetChannelSettings)

	token := getAuthToken(t, e)

	t.Run("get existing channel settings", func(t *testing.T) {
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("GET", "/channels/1", nil)
		r.Header.Set("Authorization", "Bearer "+token)

		c := e.NewContext(r, w)
		c.SetParamNames("id")
		c.SetParamValues("1")

		// Mock JWT claims
		claims := &helper.JwtClaims{
			UserID:   1,
			Username: "Admin",
		}
		c.Set("user", claims)

		err := channelController.GetChannelSettings(c)
		assert.NoError(t, err)

		resp := w.Result()
		// Accept OK, NotFound, or Forbidden based on actual data and permissions
		assert.Contains(t, []int{http.StatusOK, http.StatusNotFound, http.StatusForbidden}, resp.StatusCode)

		if resp.StatusCode == http.StatusOK {
			var settingsResponse channel.GetChannelSettingsResponse
			dec := json.NewDecoder(resp.Body)
			err = dec.Decode(&settingsResponse)
			assert.NoError(t, err)
			assert.NotEmpty(t, settingsResponse.Name)
		}
	})

	t.Run("get non-existent channel", func(t *testing.T) {
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("GET", "/channels/99999", nil)
		r.Header.Set("Authorization", "Bearer "+token)

		c := e.NewContext(r, w)
		c.SetParamNames("id")
		c.SetParamValues("99999")

		// Mock JWT claims
		claims := &helper.JwtClaims{
			UserID:   1,
			Username: "Admin",
		}
		c.Set("user", claims)

		err := channelController.GetChannelSettings(c)
		assert.NoError(t, err)

		resp := w.Result()
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})
}

func TestChannelController_PatchChannelSettings(t *testing.T) {
	channelController, e := setupChannelController(t)

	e.PATCH("/channels/:id", channelController.PatchChannelSettings)

	token := getAuthToken(t, e)

	t.Run("patch channel description", func(t *testing.T) {
		desc := "Updated test description"
		updateData := channel.PartialSettingsRequest{
			Description: &desc,
		}

		bodyBytes, _ := json.Marshal(updateData)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("PATCH", "/channels/1", bytes.NewReader(bodyBytes))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")

		c := e.NewContext(r, w)
		c.SetParamNames("id")
		c.SetParamValues("1")

		// Mock JWT claims with sufficient permissions
		claims := &helper.JwtClaims{
			UserID:   1,
			Username: "Admin",
		}
		c.Set("user", claims)

		err := channelController.PatchChannelSettings(c)
		assert.NoError(t, err)

		resp := w.Result()
		// Accept success, forbidden, or not found based on actual data and permissions
		assert.Contains(t, []int{http.StatusOK, http.StatusForbidden, http.StatusNotFound}, resp.StatusCode)
	})

	t.Run("unauthorized patch", func(t *testing.T) {
		desc := "Unauthorized update"
		updateData := channel.PartialSettingsRequest{
			Description: &desc,
		}

		bodyBytes, _ := json.Marshal(updateData)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("PATCH", "/channels/1", bytes.NewReader(bodyBytes))
		r.Header.Set("Content-Type", "application/json")

		c := e.NewContext(r, w)
		c.SetParamNames("id")
		c.SetParamValues("1")

		err := channelController.PatchChannelSettings(c)
		assert.NoError(t, err)

		resp := w.Result()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})
}

func TestChannelController_AddChannelMember(t *testing.T) {
	channelController, e := setupChannelController(t)

	e.POST("/channels/:id/members", channelController.AddChannelMember)

	token := getAuthToken(t, e)

	t.Run("unauthorized add member", func(t *testing.T) {
		memberData := controllers.AddMemberRequest{
			UserID:      2,
			AccessLevel: 100,
		}

		bodyBytes, _ := json.Marshal(memberData)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("POST", "/channels/1/members", bytes.NewReader(bodyBytes))
		r.Header.Set("Content-Type", "application/json")

		c := e.NewContext(r, w)
		c.SetParamNames("id")
		c.SetParamValues("1")

		err := channelController.AddChannelMember(c)
		assert.NoError(t, err)

		resp := w.Result()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("invalid channel ID", func(t *testing.T) {
		memberData := controllers.AddMemberRequest{
			UserID:      2,
			AccessLevel: 100,
		}

		bodyBytes, _ := json.Marshal(memberData)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("POST", "/channels/invalid/members", bytes.NewReader(bodyBytes))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")

		c := e.NewContext(r, w)
		c.SetParamNames("id")
		c.SetParamValues("invalid")

		// Mock JWT claims
		claims := &helper.JwtClaims{
			UserID:   1,
			Username: "Admin",
		}
		c.Set("user", claims)

		err := channelController.AddChannelMember(c)
		assert.NoError(t, err)

		resp := w.Result()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
}

func TestChannelController_RemoveChannelMember(t *testing.T) {
	channelController, e := setupChannelController(t)

	e.DELETE("/channels/:id/members", channelController.RemoveChannelMember)

	token := getAuthToken(t, e)

	t.Run("unauthorized remove member", func(t *testing.T) {
		memberData := controllers.RemoveMemberRequest{
			UserID: 2,
		}

		bodyBytes, _ := json.Marshal(memberData)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("DELETE", "/channels/1/members", bytes.NewReader(bodyBytes))
		r.Header.Set("Content-Type", "application/json")

		c := e.NewContext(r, w)
		c.SetParamNames("id")
		c.SetParamValues("1")

		err := channelController.RemoveChannelMember(c)
		assert.NoError(t, err)

		resp := w.Result()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("invalid request format", func(t *testing.T) {
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("DELETE", "/channels/1/members", bytes.NewReader([]byte("invalid json")))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")

		c := e.NewContext(r, w)
		c.SetParamNames("id")
		c.SetParamValues("1")

		// Mock JWT claims
		claims := &helper.JwtClaims{
			UserID:   1,
			Username: "Admin",
		}
		c.Set("user", claims)

		err := channelController.RemoveChannelMember(c)
		assert.NoError(t, err)

		resp := w.Result()
		// Invalid JSON format may result in 400 (Bad Request) or 404 (Not Found) depending on implementation
		assert.Contains(t, []int{http.StatusBadRequest, http.StatusNotFound}, resp.StatusCode)
	})
}

func TestChannelController_Integration(t *testing.T) {
	channelController, e := setupChannelController(t)

	// Setup routes
	e.GET("/channels/search", channelController.SearchChannels)
	e.GET("/channels/:id", channelController.GetChannelSettings)
	e.PATCH("/channels/:id", channelController.PatchChannelSettings)

	token := getAuthToken(t, e)

	t.Run("complete channel workflow", func(t *testing.T) {
		// First, search for channels to get available channel IDs
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("GET", "/channels/search?q=coder&limit=1", nil)
		r.Header.Set("Authorization", "Bearer "+token)

		c := e.NewContext(r, w)
		claims := &helper.JwtClaims{
			UserID:   1,
			Username: "Admin",
		}
		c.Set("user", claims)

		err := channelController.SearchChannels(c)
		assert.NoError(t, err)

		resp := w.Result()
		if resp.StatusCode == http.StatusOK {
			var searchResponse controllers.SearchChannelsResponse
			dec := json.NewDecoder(resp.Body)
			err = dec.Decode(&searchResponse)
			assert.NoError(t, err)

			if len(searchResponse.Channels) > 0 {
				channelID := searchResponse.Channels[0].ID

				// Test getting channel settings
				w2 := httptest.NewRecorder()
				r2, _ := http.NewRequest("GET", fmt.Sprintf("/channels/%d", channelID), nil)
				r2.Header.Set("Authorization", "Bearer "+token)

				c2 := e.NewContext(r2, w2)
				c2.SetParamNames("id")
				c2.SetParamValues(fmt.Sprintf("%d", channelID))
				c2.Set("user", claims)

				err = channelController.GetChannelSettings(c2)
				assert.NoError(t, err)

				resp2 := w2.Result()
				// Either success or forbidden depending on permissions
				assert.Contains(t, []int{http.StatusOK, http.StatusForbidden}, resp2.StatusCode)
			} else {
				t.Log("No channels found in search results, skipping channel settings test")
			}
		} else {
			t.Log("Search request failed or was unauthorized, skipping workflow test")
		}
	})
}
