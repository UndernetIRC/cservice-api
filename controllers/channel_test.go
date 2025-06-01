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
