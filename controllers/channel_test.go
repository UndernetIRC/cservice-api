// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package controllers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/undernetirc/cservice-api/db"
	"github.com/undernetirc/cservice-api/db/mocks"
	"github.com/undernetirc/cservice-api/internal/helper"
	"github.com/undernetirc/cservice-api/models"
)

// Helper function to create a test Echo context with JWT claims
func createTestContext(method, url string, userID int32) (echo.Context, *httptest.ResponseRecorder) {
	e := echo.New()
	e.Validator = helper.NewValidator()

	req := httptest.NewRequest(method, url, nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// Create JWT claims and add to context only if userID > 0
	if userID > 0 {
		claims := &helper.JwtClaims{
			UserID: userID,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			},
		}
		c.Set("user", &jwt.Token{Claims: claims})
	}
	// If userID is 0, don't set any user context (simulates unauthorized request)

	return c, rec
}

// Helper function to create a test Echo context with JWT claims and request body
func createTestContextWithBody(
	method, url string,
	userID int32,
	requestBody string,
) (echo.Context, *httptest.ResponseRecorder) {
	e := echo.New()
	e.Validator = helper.NewValidator()

	req := httptest.NewRequest(method, url, strings.NewReader(requestBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// Create JWT claims and add to context only if userID > 0
	if userID > 0 {
		claims := &helper.JwtClaims{
			UserID: userID,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			},
		}
		c.Set("user", &jwt.Token{Claims: claims})
	}
	// If userID is 0, don't set any user context (simulates unauthorized request)

	return c, rec
}

func TestChannelController_SearchChannels_Success(t *testing.T) {
	// Setup
	mockQuerier := mocks.NewQuerier(t)
	controller := NewChannelController(mockQuerier)

	// Mock data
	expectedChannels := []models.SearchChannelsRow{
		{
			ID:          1,
			Name:        "#test",
			Description: pgtype.Text{String: "Test channel", Valid: true},
			Url:         pgtype.Text{String: "https://example.com", Valid: true},
			CreatedAt:   pgtype.Int4{Int32: 1640995200, Valid: true}, // 2022-01-01
			MemberCount: 42,
		},
		{
			ID:          2,
			Name:        "#testing",
			Description: pgtype.Text{String: "Another test channel", Valid: true},
			Url:         pgtype.Text{Valid: false},
			CreatedAt:   pgtype.Int4{Int32: 1640995200, Valid: true},
			MemberCount: 15,
		},
	}

	// Setup mocks
	mockQuerier.On("SearchChannelsCount", mock.Anything, "%test%").Return(int64(2), nil)
	mockQuerier.On("SearchChannels", mock.Anything, models.SearchChannelsParams{
		Name:   "%test%",
		Limit:  20,
		Offset: 0,
	}).Return(expectedChannels, nil)

	// Create test context
	c, rec := createTestContext("GET", "/channels/search?q=test", 123)

	// Execute
	err := controller.SearchChannels(c)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	// Parse response
	var response SearchChannelsResponse
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	assert.NoError(t, err)

	// Verify response
	assert.Len(t, response.Channels, 2)
	assert.Equal(t, "Test channel", response.Channels[0].Description)
	assert.Equal(t, "https://example.com", response.Channels[0].URL)
	assert.Equal(t, int32(42), response.Channels[0].MemberCount)
	assert.Equal(t, "", response.Channels[1].URL) // Should be empty for invalid pgtype.Text

	// Verify pagination
	assert.Equal(t, 2, response.Pagination.Total)
	assert.Equal(t, 20, response.Pagination.Limit)
	assert.Equal(t, 0, response.Pagination.Offset)
	assert.False(t, response.Pagination.HasMore)

	mockQuerier.AssertExpectations(t)
}

func TestChannelController_SearchChannels_Unauthorized(t *testing.T) {
	// Setup
	mockQuerier := mocks.NewQuerier(t)
	controller := NewChannelController(mockQuerier)

	// Create test context without JWT claims
	c, _ := createTestContext("GET", "/channels/search?q=test", 0)

	// Execute
	err := controller.SearchChannels(c)

	// Assert
	assert.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	assert.True(t, ok)
	assert.Equal(t, http.StatusUnauthorized, httpErr.Code)
	assert.Contains(t, httpErr.Message, "Authorization information is missing")
}

func TestChannelController_SearchChannels_MissingQuery(t *testing.T) {
	// Setup
	mockQuerier := mocks.NewQuerier(t)
	controller := NewChannelController(mockQuerier)

	// Create test context without query parameter
	c, _ := createTestContext("GET", "/channels/search", 123)

	// Execute
	err := controller.SearchChannels(c)

	// Assert
	assert.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	assert.True(t, ok)
	assert.Equal(t, http.StatusBadRequest, httpErr.Code)
	assert.Contains(t, httpErr.Message, "Search query parameter 'q' is required")
}

func TestChannelController_SearchChannels_DatabaseError(t *testing.T) {
	// Setup
	mockQuerier := mocks.NewQuerier(t)
	controller := NewChannelController(mockQuerier)

	// Setup mock to return error
	mockQuerier.On("SearchChannelsCount", mock.Anything, "%test%").Return(int64(0), fmt.Errorf("database error"))

	// Create test context
	c, _ := createTestContext("GET", "/channels/search?q=test", 123)

	// Execute
	err := controller.SearchChannels(c)

	// Assert
	assert.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	assert.True(t, ok)
	assert.Equal(t, http.StatusInternalServerError, httpErr.Code)
	assert.Contains(t, httpErr.Message, "Failed to search channels")

	mockQuerier.AssertExpectations(t)
}

func TestChannelController_PrepareSearchQuery(t *testing.T) {
	controller := &ChannelController{}

	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Simple query without wildcards",
			input:    "test",
			expected: "%test%",
		},
		{
			name:     "Query with existing wildcards",
			input:    "test%",
			expected: "test%",
		},
		{
			name:     "Query with underscore wildcard",
			input:    "test_",
			expected: "test_",
		},
		{
			name:     "Empty query",
			input:    "",
			expected: "%%",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := controller.prepareSearchQuery(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestChannelController_UpdateChannelSettings_Success(t *testing.T) {
	// Setup
	mockQuerier := mocks.NewQuerier(t)
	controller := NewChannelController(mockQuerier)

	// Mock data
	channelID := int32(1)
	userID := int32(123)
	requestBody := `{"description": "Updated description", "url": "https://example.com/updated"}`

	// Setup mocks
	mockQuerier.On("CheckChannelExists", mock.Anything, channelID).Return(models.CheckChannelExistsRow{
		ID:   channelID,
		Name: "#test",
	}, nil)

	mockQuerier.On("GetChannelUserAccess", mock.Anything, channelID, userID).Return(models.GetChannelUserAccessRow{
		Access:    500,
		UserID:    userID,
		ChannelID: channelID,
	}, nil)

	mockQuerier.On("UpdateChannelSettings", mock.Anything, models.UpdateChannelSettingsParams{
		ID:          channelID,
		Description: pgtype.Text{String: "Updated description", Valid: true},
		Url:         pgtype.Text{String: "https://example.com/updated", Valid: true},
	}).Return(models.UpdateChannelSettingsRow{
		ID:          channelID,
		Name:        "#test",
		Description: pgtype.Text{String: "Updated description", Valid: true},
		Url:         pgtype.Text{String: "https://example.com/updated", Valid: true},
		CreatedAt:   pgtype.Int4{Int32: 1640995200, Valid: true},
		LastUpdated: 1640995300,
	}, nil)

	// Create test context
	c, rec := createTestContext("PUT", "/channels/1", userID)
	c.SetParamNames("id")
	c.SetParamValues("1")

	// Properly set up the request body
	req := httptest.NewRequest("PUT", "/channels/1", strings.NewReader(requestBody))
	req.Header.Set("Content-Type", "application/json")
	c.SetRequest(req)

	// Execute
	err := controller.UpdateChannelSettings(c)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	// Parse response
	var response UpdateChannelSettingsResponse
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	assert.NoError(t, err)

	// Verify response
	assert.Equal(t, channelID, response.ID)
	assert.Equal(t, "#test", response.Name)
	assert.Equal(t, "Updated description", response.Description)
	assert.Equal(t, "https://example.com/updated", response.URL)
	assert.Equal(t, int32(1640995300), response.UpdatedAt)

	mockQuerier.AssertExpectations(t)
}

func TestChannelController_UpdateChannelSettings_PartialUpdate(t *testing.T) {
	// Setup
	mockQuerier := mocks.NewQuerier(t)
	controller := NewChannelController(mockQuerier)

	// Mock data - only updating description
	channelID := int32(1)
	userID := int32(123)
	requestBody := `{"description": "New description only"}`

	// Setup mocks
	mockQuerier.On("CheckChannelExists", mock.Anything, channelID).Return(models.CheckChannelExistsRow{
		ID:   channelID,
		Name: "#test",
	}, nil)

	mockQuerier.On("GetChannelUserAccess", mock.Anything, channelID, userID).Return(models.GetChannelUserAccessRow{
		Access:    500,
		UserID:    userID,
		ChannelID: channelID,
	}, nil)

	// Need to get current channel data to preserve URL
	mockQuerier.On("GetChannelByID", mock.Anything, channelID).Return(models.GetChannelByIDRow{
		ID:          channelID,
		Name:        "#test",
		Description: pgtype.Text{String: "Old description", Valid: true},
		Url:         pgtype.Text{String: "https://example.com/old", Valid: true},
		CreatedAt:   pgtype.Int4{Int32: 1640995200, Valid: true},
		MemberCount: 42,
	}, nil)

	mockQuerier.On("UpdateChannelSettings", mock.Anything, models.UpdateChannelSettingsParams{
		ID:          channelID,
		Description: pgtype.Text{String: "New description only", Valid: true},
		Url:         pgtype.Text{String: "https://example.com/old", Valid: true}, // Preserved
	}).Return(models.UpdateChannelSettingsRow{
		ID:          channelID,
		Name:        "#test",
		Description: pgtype.Text{String: "New description only", Valid: true},
		Url:         pgtype.Text{String: "https://example.com/old", Valid: true},
		CreatedAt:   pgtype.Int4{Int32: 1640995200, Valid: true},
		LastUpdated: 1640995300,
	}, nil)

	// Create test context
	c, rec := createTestContextWithBody("PUT", "/channels/1", userID, requestBody)
	c.SetParamNames("id")
	c.SetParamValues("1")

	// Execute
	err := controller.UpdateChannelSettings(c)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	mockQuerier.AssertExpectations(t)
}

func TestChannelController_UpdateChannelSettings_Unauthorized(t *testing.T) {
	// Setup
	mockQuerier := mocks.NewQuerier(t)
	controller := NewChannelController(mockQuerier)

	// Create test context without JWT claims
	c, _ := createTestContext("PUT", "/channels/1", 0)
	c.SetParamNames("id")
	c.SetParamValues("1")

	// Execute
	err := controller.UpdateChannelSettings(c)

	// Assert
	assert.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	assert.True(t, ok)
	assert.Equal(t, http.StatusUnauthorized, httpErr.Code)
}

func TestChannelController_UpdateChannelSettings_InvalidChannelID(t *testing.T) {
	// Setup
	mockQuerier := mocks.NewQuerier(t)
	controller := NewChannelController(mockQuerier)

	// Create test context with invalid channel ID
	c, _ := createTestContext("PUT", "/channels/invalid", 123)
	c.SetParamNames("id")
	c.SetParamValues("invalid")

	// Execute
	err := controller.UpdateChannelSettings(c)

	// Assert
	assert.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	assert.True(t, ok)
	assert.Equal(t, http.StatusBadRequest, httpErr.Code)
	assert.Contains(t, httpErr.Message, "Invalid channel ID")
}

func TestChannelController_UpdateChannelSettings_ChannelNotFound(t *testing.T) {
	// Setup
	mockQuerier := mocks.NewQuerier(t)
	controller := NewChannelController(mockQuerier)

	channelID := int32(999)
	requestBody := `{"description": "test"}`

	// Setup mock - channel doesn't exist
	mockQuerier.On("CheckChannelExists", mock.Anything, channelID).
		Return(models.CheckChannelExistsRow{}, fmt.Errorf("no rows found"))

	// Create test context
	c, _ := createTestContextWithBody("PUT", "/channels/999", 123, requestBody)
	c.SetParamNames("id")
	c.SetParamValues("999")

	// Execute
	err := controller.UpdateChannelSettings(c)

	// Assert
	assert.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	assert.True(t, ok)
	assert.Equal(t, http.StatusNotFound, httpErr.Code)
	assert.Contains(t, httpErr.Message, "Channel not found")

	mockQuerier.AssertExpectations(t)
}

func TestChannelController_UpdateChannelSettings_InsufficientAccess(t *testing.T) {
	// Setup
	mockQuerier := mocks.NewQuerier(t)
	controller := NewChannelController(mockQuerier)

	channelID := int32(1)
	userID := int32(123)
	requestBody := `{"description": "test"}`

	// Setup mocks
	mockQuerier.On("CheckChannelExists", mock.Anything, channelID).Return(models.CheckChannelExistsRow{
		ID:   channelID,
		Name: "#test",
	}, nil)

	// User has insufficient access (< 500)
	mockQuerier.On("GetChannelUserAccess", mock.Anything, channelID, userID).Return(models.GetChannelUserAccessRow{
		Access:    100, // Too low
		UserID:    userID,
		ChannelID: channelID,
	}, nil)

	// Create test context
	c, _ := createTestContextWithBody("PUT", "/channels/1", userID, requestBody)
	c.SetParamNames("id")
	c.SetParamValues("1")

	// Execute
	err := controller.UpdateChannelSettings(c)

	// Assert
	assert.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	assert.True(t, ok)
	assert.Equal(t, http.StatusForbidden, httpErr.Code)
	assert.Contains(t, httpErr.Message, "Insufficient permissions")

	mockQuerier.AssertExpectations(t)
}

func TestChannelController_UpdateChannelSettings_ValidationErrors(t *testing.T) {
	// Setup
	mockQuerier := mocks.NewQuerier(t)
	controller := NewChannelController(mockQuerier)

	testCases := []struct {
		name        string
		requestBody string
		expectError string
	}{
		{
			name:        "Description too long",
			requestBody: `{"description": "` + strings.Repeat("a", 501) + `"}`,
			expectError: "max",
		},
		{
			name:        "Invalid URL format",
			requestBody: `{"url": "not-a-valid-url"}`,
			expectError: "url",
		},
		{
			name:        "URL too long",
			requestBody: `{"url": "https://example.com/` + strings.Repeat("a", 300) + `"}`,
			expectError: "max",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create test context
			c, _ := createTestContextWithBody("PUT", "/channels/1", 123, tc.requestBody)
			c.SetParamNames("id")
			c.SetParamValues("1")

			// Execute
			err := controller.UpdateChannelSettings(c)

			// Assert
			assert.Error(t, err)
			httpErr, ok := err.(*echo.HTTPError)
			assert.True(t, ok)
			assert.Equal(t, http.StatusBadRequest, httpErr.Code)
			assert.Contains(t, strings.ToLower(httpErr.Message.(string)), tc.expectError)
		})
	}
}

func TestChannelController_GetChannelSettings_Success(t *testing.T) {
	// Setup
	mockQuerier := mocks.NewQuerier(t)
	controller := NewChannelController(mockQuerier)

	// Mock data
	channelID := int32(1)
	userID := int32(123)

	// Setup mocks
	mockQuerier.On("GetChannelDetails", mock.Anything, channelID).Return(models.GetChannelDetailsRow{
		ID:          channelID,
		Name:        "#test",
		Description: pgtype.Text{String: "Test channel description", Valid: true},
		Url:         pgtype.Text{String: "https://example.com", Valid: true},
		CreatedAt:   pgtype.Int4{Int32: 1640995200, Valid: true},
		LastUpdated: 1640995300,
		MemberCount: 42,
	}, nil)

	mockQuerier.On("GetChannelUserAccess", mock.Anything, channelID, userID).Return(models.GetChannelUserAccessRow{
		Access:    250, // Sufficient for viewing (>= 100)
		UserID:    userID,
		ChannelID: channelID,
	}, nil)

	// Create test context
	c, rec := createTestContext("GET", "/channels/1", userID)
	c.SetParamNames("id")
	c.SetParamValues("1")

	// Execute
	err := controller.GetChannelSettings(c)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	// Parse response
	var response GetChannelSettingsResponse
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	assert.NoError(t, err)

	// Verify response
	assert.Equal(t, channelID, response.ID)
	assert.Equal(t, "#test", response.Name)
	assert.Equal(t, "Test channel description", response.Description)
	assert.Equal(t, "https://example.com", response.URL)
	assert.Equal(t, int32(42), response.MemberCount)
	assert.Equal(t, int32(1640995200), response.CreatedAt)
	assert.Equal(t, int32(1640995300), response.UpdatedAt)

	mockQuerier.AssertExpectations(t)
}

func TestChannelController_GetChannelSettings_WithoutUpdatedTime(t *testing.T) {
	// Setup
	mockQuerier := mocks.NewQuerier(t)
	controller := NewChannelController(mockQuerier)

	// Mock data
	channelID := int32(1)
	userID := int32(123)

	// Setup mocks - channel without update timestamp
	mockQuerier.On("GetChannelDetails", mock.Anything, channelID).Return(models.GetChannelDetailsRow{
		ID:          channelID,
		Name:        "#test",
		Description: pgtype.Text{String: "Test channel", Valid: true},
		Url:         pgtype.Text{Valid: false}, // No URL
		CreatedAt:   pgtype.Int4{Int32: 1640995200, Valid: true},
		LastUpdated: 0, // No update timestamp
		MemberCount: 10,
	}, nil)

	mockQuerier.On("GetChannelUserAccess", mock.Anything, channelID, userID).Return(models.GetChannelUserAccessRow{
		Access:    100, // Minimum required access
		UserID:    userID,
		ChannelID: channelID,
	}, nil)

	// Create test context
	c, rec := createTestContext("GET", "/channels/1", userID)
	c.SetParamNames("id")
	c.SetParamValues("1")

	// Execute
	err := controller.GetChannelSettings(c)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	// Parse response
	var response GetChannelSettingsResponse
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	assert.NoError(t, err)

	// Verify response
	assert.Equal(t, "#test", response.Name)
	assert.Equal(t, "Test channel", response.Description)
	assert.Equal(t, "", response.URL)             // Should be empty for invalid pgtype.Text
	assert.Equal(t, int32(0), response.UpdatedAt) // Should be 0 for no updates

	mockQuerier.AssertExpectations(t)
}

func TestChannelController_GetChannelSettings_Unauthorized(t *testing.T) {
	// Setup
	mockQuerier := mocks.NewQuerier(t)
	controller := NewChannelController(mockQuerier)

	// Create test context without JWT claims
	c, _ := createTestContext("GET", "/channels/1", 0)
	c.SetParamNames("id")
	c.SetParamValues("1")

	// Execute
	err := controller.GetChannelSettings(c)

	// Assert
	assert.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	assert.True(t, ok)
	assert.Equal(t, http.StatusUnauthorized, httpErr.Code)
	assert.Contains(t, httpErr.Message, "Authorization information is missing")
}

func TestChannelController_GetChannelSettings_InvalidChannelID(t *testing.T) {
	// Setup
	mockQuerier := mocks.NewQuerier(t)
	controller := NewChannelController(mockQuerier)

	testCases := []struct {
		name      string
		channelID string
	}{
		{"Non-numeric ID", "invalid"},
		{"Negative ID", "-1"},
		{"Zero ID", "0"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create test context
			c, _ := createTestContext("GET", "/channels/"+tc.channelID, 123)
			c.SetParamNames("id")
			c.SetParamValues(tc.channelID)

			// Execute
			err := controller.GetChannelSettings(c)

			// Assert
			assert.Error(t, err)
			httpErr, ok := err.(*echo.HTTPError)
			assert.True(t, ok)
			assert.Equal(t, http.StatusBadRequest, httpErr.Code)
			assert.Contains(t, httpErr.Message, "Invalid channel ID")
		})
	}
}

func TestChannelController_GetChannelSettings_ChannelNotFound(t *testing.T) {
	// Setup
	mockQuerier := mocks.NewQuerier(t)
	controller := NewChannelController(mockQuerier)

	channelID := int32(999)

	// Setup mock - channel doesn't exist
	mockQuerier.On("GetChannelDetails", mock.Anything, channelID).
		Return(models.GetChannelDetailsRow{}, fmt.Errorf("no rows found"))

	// Create test context
	c, _ := createTestContext("GET", "/channels/999", 123)
	c.SetParamNames("id")
	c.SetParamValues("999")

	// Execute
	err := controller.GetChannelSettings(c)

	// Assert
	assert.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	assert.True(t, ok)
	assert.Equal(t, http.StatusNotFound, httpErr.Code)
	assert.Contains(t, httpErr.Message, "Channel not found")

	mockQuerier.AssertExpectations(t)
}

func TestChannelController_GetChannelSettings_InsufficientAccess(t *testing.T) {
	// Setup
	mockQuerier := mocks.NewQuerier(t)
	controller := NewChannelController(mockQuerier)

	channelID := int32(1)
	userID := int32(123)

	// Setup mocks
	mockQuerier.On("GetChannelDetails", mock.Anything, channelID).Return(models.GetChannelDetailsRow{
		ID:   channelID,
		Name: "#test",
	}, nil)

	// User has insufficient access (< 100)
	mockQuerier.On("GetChannelUserAccess", mock.Anything, channelID, userID).Return(models.GetChannelUserAccessRow{
		Access:    50, // Too low for viewing
		UserID:    userID,
		ChannelID: channelID,
	}, nil)

	// Create test context
	c, _ := createTestContext("GET", "/channels/1", userID)
	c.SetParamNames("id")
	c.SetParamValues("1")

	// Execute
	err := controller.GetChannelSettings(c)

	// Assert
	assert.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	assert.True(t, ok)
	assert.Equal(t, http.StatusForbidden, httpErr.Code)
	assert.Contains(t, httpErr.Message, "Insufficient permissions")

	mockQuerier.AssertExpectations(t)
}

func TestChannelController_GetChannelSettings_UserNotInChannel(t *testing.T) {
	// Setup
	mockQuerier := mocks.NewQuerier(t)
	controller := NewChannelController(mockQuerier)

	channelID := int32(1)
	userID := int32(123)

	// Setup mocks
	mockQuerier.On("GetChannelDetails", mock.Anything, channelID).Return(models.GetChannelDetailsRow{
		ID:   channelID,
		Name: "#test",
	}, nil)

	// User not found in channel
	mockQuerier.On("GetChannelUserAccess", mock.Anything, channelID, userID).
		Return(models.GetChannelUserAccessRow{}, fmt.Errorf("no rows found"))

	// Create test context
	c, _ := createTestContext("GET", "/channels/1", userID)
	c.SetParamNames("id")
	c.SetParamValues("1")

	// Execute
	err := controller.GetChannelSettings(c)

	// Assert
	assert.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	assert.True(t, ok)
	assert.Equal(t, http.StatusForbidden, httpErr.Code)
	assert.Contains(t, httpErr.Message, "Insufficient permissions")

	mockQuerier.AssertExpectations(t)
}

func TestAddChannelMember_Success(t *testing.T) {
	// Setup
	e := echo.New()
	e.Validator = helper.NewValidator()
	mockService := mocks.NewQuerier(t)
	controller := NewChannelController(mockService)

	// Test data
	channelID := int32(1)
	userID := int32(2)
	accessLevel := int32(200)
	requesterUserID := int32(3)
	requesterAccess := int32(300)

	// Mock JWT claims
	claims := &helper.JwtClaims{
		UserID:   requesterUserID,
		Username: "testuser",
	}

	// Request body
	reqBody := AddMemberRequest{
		UserID:      int64(userID),
		AccessLevel: int(accessLevel),
	}
	reqJSON, _ := json.Marshal(reqBody)

	// Create request
	req := httptest.NewRequest(http.MethodPost, "/channels/1/members", bytes.NewReader(reqJSON))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues("1")

	// Set JWT token in context
	token := &jwt.Token{Claims: claims}
	c.Set("user", token)

	// Mock expectations
	mockService.On("GetChannelByName", mock.Anything, "*").Return(models.GetChannelByNameRow{}, assert.AnError)
	mockService.On("CheckChannelExists", mock.Anything, channelID).
		Return(models.CheckChannelExistsRow{ID: channelID}, nil)
	mockService.On("GetChannelUserAccess", mock.Anything, channelID, requesterUserID).
		Return(models.GetChannelUserAccessRow{
			Access:    requesterAccess,
			UserID:    requesterUserID,
			ChannelID: channelID,
		}, nil)
	mockService.On("GetChannelUserAccess", mock.Anything, channelID, userID).
		Return(models.GetChannelUserAccessRow{}, assert.AnError)
	mockService.On("CheckChannelMemberExists", mock.Anything, channelID, userID).
		Return(models.CheckChannelMemberExistsRow{}, assert.AnError)
	mockService.On("AddChannelMember", mock.Anything, mock.MatchedBy(func(params models.AddChannelMemberParams) bool {
		return params.ChannelID == channelID && params.UserID == userID && params.Access == accessLevel
	})).Return(models.AddChannelMemberRow{
		ChannelID: channelID,
		UserID:    userID,
		Access:    accessLevel,
		Added:     db.NewInt4(1640995200), // Mock timestamp
	}, nil)

	// Execute
	err := controller.AddChannelMember(c)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, http.StatusCreated, rec.Code)

	var response AddMemberResponse
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, channelID, response.ChannelID)
	assert.Equal(t, int64(userID), response.UserID)
	assert.Equal(t, int(accessLevel), response.AccessLevel)
	assert.Equal(t, "Member added successfully", response.Message)

	mockService.AssertExpectations(t)
}

func TestAddChannelMember_ProtectedChannel(t *testing.T) {
	// Setup
	e := echo.New()
	e.Validator = helper.NewValidator()
	mockService := mocks.NewQuerier(t)
	controller := NewChannelController(mockService)

	// Test data - using the special "*" channel
	channelID := int32(999) // Assume this is the ID of the "*" channel
	userID := int32(2)
	requesterUserID := int32(3)

	// Mock JWT claims
	claims := &helper.JwtClaims{
		UserID:   requesterUserID,
		Username: "testuser",
	}

	// Request body
	reqBody := AddMemberRequest{
		UserID:      int64(userID),
		AccessLevel: 200,
	}
	reqJSON, _ := json.Marshal(reqBody)

	// Create request
	req := httptest.NewRequest(http.MethodPost, "/channels/999/members", bytes.NewReader(reqJSON))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues("999")

	// Set JWT token in context
	token := &jwt.Token{Claims: claims}
	c.Set("user", token)

	// Mock expectations - return the "*" channel when queried by name
	mockService.On("GetChannelByName", mock.Anything, "*").Return(models.GetChannelByNameRow{
		ID:   channelID,
		Name: "*",
	}, nil)

	// Execute
	err := controller.AddChannelMember(c)

	// Assert - should return 404 to hide the existence of the special channel
	assert.IsType(t, &echo.HTTPError{}, err)
	httpErr := err.(*echo.HTTPError)
	assert.Equal(t, http.StatusNotFound, httpErr.Code)
	assert.Equal(t, "Channel not found", httpErr.Message)

	mockService.AssertExpectations(t)
}

func TestAddChannelMember_InsufficientPermissions(t *testing.T) {
	// Setup
	e := echo.New()
	e.Validator = helper.NewValidator()
	mockService := mocks.NewQuerier(t)
	controller := NewChannelController(mockService)

	// Test data
	channelID := int32(1)
	userID := int32(2)
	requesterUserID := int32(3)
	requesterAccess := int32(50) // Below minimum required (100)

	// Mock JWT claims
	claims := &helper.JwtClaims{
		UserID:   requesterUserID,
		Username: "testuser",
	}

	// Request body
	reqBody := AddMemberRequest{
		UserID:      int64(userID),
		AccessLevel: 200,
	}
	reqJSON, _ := json.Marshal(reqBody)

	// Create request
	req := httptest.NewRequest(http.MethodPost, "/channels/1/members", bytes.NewReader(reqJSON))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues("1")

	// Set JWT token in context
	token := &jwt.Token{Claims: claims}
	c.Set("user", token)

	// Mock expectations
	mockService.On("GetChannelByName", mock.Anything, "*").Return(models.GetChannelByNameRow{}, assert.AnError)
	mockService.On("CheckChannelExists", mock.Anything, channelID).
		Return(models.CheckChannelExistsRow{ID: channelID}, nil)
	mockService.On("GetChannelUserAccess", mock.Anything, channelID, requesterUserID).
		Return(models.GetChannelUserAccessRow{
			Access:    requesterAccess,
			UserID:    requesterUserID,
			ChannelID: channelID,
		}, nil)

	// Execute
	err := controller.AddChannelMember(c)

	// Assert
	assert.IsType(t, &echo.HTTPError{}, err)
	httpErr := err.(*echo.HTTPError)
	assert.Equal(t, http.StatusForbidden, httpErr.Code)
	assert.Equal(t, "Insufficient permissions to add members", httpErr.Message)

	mockService.AssertExpectations(t)
}

func TestAddChannelMember_CannotAddHigherLevel(t *testing.T) {
	// Setup
	e := echo.New()
	e.Validator = helper.NewValidator()
	mockService := mocks.NewQuerier(t)
	controller := NewChannelController(mockService)

	// Test data
	channelID := int32(1)
	userID := int32(2)
	requesterUserID := int32(3)
	requesterAccess := int32(200)
	requestedAccessLevel := 300 // Higher than requester's level

	// Mock JWT claims
	claims := &helper.JwtClaims{
		UserID:   requesterUserID,
		Username: "testuser",
	}

	// Request body
	reqBody := AddMemberRequest{
		UserID:      int64(userID),
		AccessLevel: requestedAccessLevel,
	}
	reqJSON, _ := json.Marshal(reqBody)

	// Create request
	req := httptest.NewRequest(http.MethodPost, "/channels/1/members", bytes.NewReader(reqJSON))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues("1")

	// Set JWT token in context
	token := &jwt.Token{Claims: claims}
	c.Set("user", token)

	// Mock expectations
	mockService.On("GetChannelByName", mock.Anything, "*").Return(models.GetChannelByNameRow{}, assert.AnError)
	mockService.On("CheckChannelExists", mock.Anything, channelID).
		Return(models.CheckChannelExistsRow{ID: channelID}, nil)
	mockService.On("GetChannelUserAccess", mock.Anything, channelID, requesterUserID).
		Return(models.GetChannelUserAccessRow{
			Access:    requesterAccess,
			UserID:    requesterUserID,
			ChannelID: channelID,
		}, nil)

	// Execute
	err := controller.AddChannelMember(c)

	// Assert
	assert.IsType(t, &echo.HTTPError{}, err)
	httpErr := err.(*echo.HTTPError)
	assert.Equal(t, http.StatusUnprocessableEntity, httpErr.Code)
	assert.Equal(t, "Cannot add user with access level higher than or equal to your own", httpErr.Message)

	mockService.AssertExpectations(t)
}

func TestAddChannelMember_UserAlreadyExists(t *testing.T) {
	// Setup
	e := echo.New()
	e.Validator = helper.NewValidator()
	mockService := mocks.NewQuerier(t)
	controller := NewChannelController(mockService)

	// Test data
	channelID := int32(1)
	userID := int32(2)
	requesterUserID := int32(3)
	requesterAccess := int32(300)

	// Mock JWT claims
	claims := &helper.JwtClaims{
		UserID:   requesterUserID,
		Username: "testuser",
	}

	// Request body
	reqBody := AddMemberRequest{
		UserID:      int64(userID),
		AccessLevel: 200,
	}
	reqJSON, _ := json.Marshal(reqBody)

	// Create request
	req := httptest.NewRequest(http.MethodPost, "/channels/1/members", bytes.NewReader(reqJSON))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues("1")

	// Set JWT token in context
	token := &jwt.Token{Claims: claims}
	c.Set("user", token)

	// Mock expectations
	mockService.On("GetChannelByName", mock.Anything, "*").Return(models.GetChannelByNameRow{}, assert.AnError)
	mockService.On("CheckChannelExists", mock.Anything, channelID).
		Return(models.CheckChannelExistsRow{ID: channelID}, nil)
	mockService.On("GetChannelUserAccess", mock.Anything, channelID, requesterUserID).
		Return(models.GetChannelUserAccessRow{
			Access:    requesterAccess,
			UserID:    requesterUserID,
			ChannelID: channelID,
		}, nil)
	// User already has access - return success instead of error
	mockService.On("GetChannelUserAccess", mock.Anything, channelID, userID).Return(models.GetChannelUserAccessRow{
		Access:    int32(150),
		UserID:    userID,
		ChannelID: channelID,
	}, nil)

	// Execute
	err := controller.AddChannelMember(c)

	// Assert
	assert.IsType(t, &echo.HTTPError{}, err)
	httpErr := err.(*echo.HTTPError)
	assert.Equal(t, http.StatusConflict, httpErr.Code)
	assert.Equal(t, "User is already a member of this channel", httpErr.Message)

	mockService.AssertExpectations(t)
}
