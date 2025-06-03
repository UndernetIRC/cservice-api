// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package controllers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/undernetirc/cservice-api/internal/helper"
	"github.com/undernetirc/cservice-api/models"
)

// MockQuerier is a simplified mock implementation for testing channel search
type MockQuerier struct {
	mock.Mock
}

func (m *MockQuerier) SearchChannels(ctx context.Context, arg models.SearchChannelsParams) ([]models.SearchChannelsRow, error) {
	args := m.Called(ctx, arg)
	return args.Get(0).([]models.SearchChannelsRow), args.Error(1)
}

func (m *MockQuerier) SearchChannelsCount(ctx context.Context, name string) (int64, error) {
	args := m.Called(ctx, name)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockQuerier) GetChannelByID(ctx context.Context, id int32) (models.GetChannelByIDRow, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(models.GetChannelByIDRow), args.Error(1)
}

// Implement all other required methods as no-ops for testing
func (m *MockQuerier) AddUserRole(ctx context.Context, userID int32, roleID int32) error { return nil }
func (m *MockQuerier) AddUsersToRole(ctx context.Context, arg []models.AddUsersToRoleParams) (int64, error) {
	return 0, nil
}
func (m *MockQuerier) CheckEmailExists(ctx context.Context, email string) ([]pgtype.Text, error) {
	return nil, nil
}
func (m *MockQuerier) CheckUsernameExists(ctx context.Context, username string) ([]string, error) {
	return nil, nil
}
func (m *MockQuerier) CreatePendingUser(ctx context.Context, arg models.CreatePendingUserParams) (pgtype.Text, error) {
	return pgtype.Text{}, nil
}
func (m *MockQuerier) CreateRole(ctx context.Context, arg models.CreateRoleParams) (models.Role, error) {
	return models.Role{}, nil
}
func (m *MockQuerier) CreateUser(ctx context.Context, arg models.CreateUserParams) (models.User, error) {
	return models.User{}, nil
}
func (m *MockQuerier) DeletePendingUserByCookie(ctx context.Context, cookie pgtype.Text) error {
	return nil
}
func (m *MockQuerier) DeleteRole(ctx context.Context, id int32) error { return nil }
func (m *MockQuerier) GetAdminLevel(ctx context.Context, userID int32) (models.GetAdminLevelRow, error) {
	return models.GetAdminLevelRow{}, nil
}
func (m *MockQuerier) GetGlineByIP(ctx context.Context, host string) (models.Gline, error) {
	return models.Gline{}, nil
}
func (m *MockQuerier) GetPendingUserByCookie(ctx context.Context, cookie pgtype.Text) (models.Pendinguser, error) {
	return models.Pendinguser{}, nil
}
func (m *MockQuerier) GetRoleByID(ctx context.Context, id int32) (models.Role, error) {
	return models.Role{}, nil
}
func (m *MockQuerier) GetRoleByName(ctx context.Context, name string) (models.Role, error) {
	return models.Role{}, nil
}
func (m *MockQuerier) GetUser(ctx context.Context, arg models.GetUserParams) (models.GetUserRow, error) {
	return models.GetUserRow{}, nil
}
func (m *MockQuerier) GetUserByEmail(ctx context.Context, email string) (models.User, error) {
	return models.User{}, nil
}
func (m *MockQuerier) GetUserByID(ctx context.Context, id int32) (models.GetUserByIDRow, error) {
	return models.GetUserByIDRow{}, nil
}
func (m *MockQuerier) GetUserByUsername(ctx context.Context, username string) (models.User, error) {
	return models.User{}, nil
}
func (m *MockQuerier) GetUserChannels(ctx context.Context, userID int32) ([]models.GetUserChannelsRow, error) {
	return nil, nil
}
func (m *MockQuerier) GetUsersByUsernames(ctx context.Context, userids []string) ([]models.GetUsersByUsernamesRow, error) {
	return nil, nil
}
func (m *MockQuerier) GetWhiteListByIP(ctx context.Context, ip netip.Addr) (models.Whitelist, error) {
	args := m.Called(ctx, ip)
	return args.Get(0).(models.Whitelist), args.Error(1)
}
func (m *MockQuerier) ListPendingUsers(ctx context.Context) ([]models.Pendinguser, error) {
	return nil, nil
}
func (m *MockQuerier) ListRoles(ctx context.Context) ([]models.Role, error) { return nil, nil }
func (m *MockQuerier) ListUserRoles(ctx context.Context, userID int32) ([]models.Role, error) {
	return nil, nil
}
func (m *MockQuerier) RemoveUserRole(ctx context.Context, userID int32, roleID int32) error {
	return nil
}
func (m *MockQuerier) RemoveUsersFromRole(ctx context.Context, userIds []int32, roleID int32) error {
	return nil
}
func (m *MockQuerier) UpdateRole(ctx context.Context, arg models.UpdateRoleParams) error { return nil }
func (m *MockQuerier) UpdateUserFlags(ctx context.Context, arg models.UpdateUserFlagsParams) error {
	return nil
}
func (m *MockQuerier) UpdateUserPassword(ctx context.Context, arg models.UpdateUserPasswordParams) error {
	return nil
}
func (m *MockQuerier) UpdateUserTotpKey(ctx context.Context, arg models.UpdateUserTotpKeyParams) error {
	return nil
}

// Add the new channel-related methods
func (m *MockQuerier) UpdateChannelSettings(ctx context.Context, arg models.UpdateChannelSettingsParams) (models.UpdateChannelSettingsRow, error) {
	args := m.Called(ctx, arg)
	return args.Get(0).(models.UpdateChannelSettingsRow), args.Error(1)
}

func (m *MockQuerier) GetChannelUserAccess(ctx context.Context, channelID int32, userID int32) (models.GetChannelUserAccessRow, error) {
	args := m.Called(ctx, channelID, userID)
	return args.Get(0).(models.GetChannelUserAccessRow), args.Error(1)
}

func (m *MockQuerier) CheckChannelExists(ctx context.Context, id int32) (models.CheckChannelExistsRow, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(models.CheckChannelExistsRow), args.Error(1)
}

func (m *MockQuerier) GetChannelDetails(ctx context.Context, id int32) (models.GetChannelDetailsRow, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(models.GetChannelDetailsRow), args.Error(1)
}

// Password reset token methods (stub implementations for testing)
func (m *MockQuerier) CreatePasswordResetToken(ctx context.Context, arg models.CreatePasswordResetTokenParams) (models.PasswordResetToken, error) {
	return models.PasswordResetToken{}, nil
}

func (m *MockQuerier) GetPasswordResetTokenByToken(ctx context.Context, token string) (models.PasswordResetToken, error) {
	return models.PasswordResetToken{}, nil
}

func (m *MockQuerier) GetActivePasswordResetTokensByUserID(ctx context.Context, userID pgtype.Int4, expiresAt int32) ([]models.PasswordResetToken, error) {
	return nil, nil
}

func (m *MockQuerier) ValidatePasswordResetToken(ctx context.Context, token string, expiresAt int32) (models.PasswordResetToken, error) {
	return models.PasswordResetToken{}, nil
}

func (m *MockQuerier) MarkPasswordResetTokenAsUsed(ctx context.Context, arg models.MarkPasswordResetTokenAsUsedParams) error {
	return nil
}

func (m *MockQuerier) InvalidateUserPasswordResetTokens(ctx context.Context, userID pgtype.Int4, lastUpdated int32) error {
	return nil
}

func (m *MockQuerier) CleanupExpiredPasswordResetTokens(ctx context.Context, expiresAt int32, lastUpdated int32) error {
	return nil
}

func (m *MockQuerier) DeleteExpiredPasswordResetTokens(ctx context.Context, expiresAt int32) error {
	return nil
}

func (m *MockQuerier) GetPasswordResetTokenStats(ctx context.Context, expiresAt int32) (models.GetPasswordResetTokenStatsRow, error) {
	return models.GetPasswordResetTokenStatsRow{}, nil
}

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
func createTestContextWithBody(method, url string, userID int32, requestBody string) (echo.Context, *httptest.ResponseRecorder) {
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
	mockQuerier := new(MockQuerier)
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
	mockQuerier := new(MockQuerier)
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
	mockQuerier := new(MockQuerier)
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
	mockQuerier := new(MockQuerier)
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
	mockQuerier := new(MockQuerier)
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
	mockQuerier := new(MockQuerier)
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
	mockQuerier := new(MockQuerier)
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
	mockQuerier := new(MockQuerier)
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
	mockQuerier := new(MockQuerier)
	controller := NewChannelController(mockQuerier)

	channelID := int32(999)
	requestBody := `{"description": "test"}`

	// Setup mock - channel doesn't exist
	mockQuerier.On("CheckChannelExists", mock.Anything, channelID).Return(models.CheckChannelExistsRow{}, fmt.Errorf("no rows found"))

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
	mockQuerier := new(MockQuerier)
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
	mockQuerier := new(MockQuerier)
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
	mockQuerier := new(MockQuerier)
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
	mockQuerier := new(MockQuerier)
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
	mockQuerier := new(MockQuerier)
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
	mockQuerier := new(MockQuerier)
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
	mockQuerier := new(MockQuerier)
	controller := NewChannelController(mockQuerier)

	channelID := int32(999)

	// Setup mock - channel doesn't exist
	mockQuerier.On("GetChannelDetails", mock.Anything, channelID).Return(models.GetChannelDetailsRow{}, fmt.Errorf("no rows found"))

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
	mockQuerier := new(MockQuerier)
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
	mockQuerier := new(MockQuerier)
	controller := NewChannelController(mockQuerier)

	channelID := int32(1)
	userID := int32(123)

	// Setup mocks
	mockQuerier.On("GetChannelDetails", mock.Anything, channelID).Return(models.GetChannelDetailsRow{
		ID:   channelID,
		Name: "#test",
	}, nil)

	// User not found in channel
	mockQuerier.On("GetChannelUserAccess", mock.Anything, channelID, userID).Return(models.GetChannelUserAccessRow{}, fmt.Errorf("no rows found"))

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
