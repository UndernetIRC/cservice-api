// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package controllers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/undernetirc/cservice-api/db"
	"github.com/undernetirc/cservice-api/db/mocks"
	"github.com/undernetirc/cservice-api/internal/config"
	apierrors "github.com/undernetirc/cservice-api/internal/errors"
	"github.com/undernetirc/cservice-api/internal/helper"
	"github.com/undernetirc/cservice-api/models"
)

// MockPool implements PoolInterface for testing
type MockPool struct {
	mock.Mock
}

func (m *MockPool) Begin(ctx context.Context) (pgx.Tx, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(pgx.Tx), args.Error(1)
}

// createMockPool creates a simple mock pool for tests that don't need transaction functionality
func createMockPool() *MockPool {
	mockPool := &MockPool{}
	// For most tests, we don't expect Begin to be called
	mockPool.On("Begin", mock.Anything).Return(nil, fmt.Errorf("transactions not supported in this test")).Maybe()
	return mockPool
}

// MockTx implements pgx.Tx for testing
type MockTx struct {
	mock.Mock
}

func (m *MockTx) Begin(ctx context.Context) (pgx.Tx, error) {
	args := m.Called(ctx)
	return args.Get(0).(pgx.Tx), args.Error(1)
}

func (m *MockTx) Commit(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockTx) Rollback(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockTx) CopyFrom(ctx context.Context, tableName pgx.Identifier, columnNames []string, rowSrc pgx.CopyFromSource) (int64, error) {
	args := m.Called(ctx, tableName, columnNames, rowSrc)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockTx) SendBatch(ctx context.Context, b *pgx.Batch) pgx.BatchResults {
	args := m.Called(ctx, b)
	return args.Get(0).(pgx.BatchResults)
}

func (m *MockTx) LargeObjects() pgx.LargeObjects {
	args := m.Called()
	return args.Get(0).(pgx.LargeObjects)
}

func (m *MockTx) Prepare(ctx context.Context, name, sql string) (*pgconn.StatementDescription, error) {
	args := m.Called(ctx, name, sql)
	return args.Get(0).(*pgconn.StatementDescription), args.Error(1)
}

func (m *MockTx) Exec(ctx context.Context, sql string, arguments ...interface{}) (pgconn.CommandTag, error) {
	args := m.Called(ctx, sql, arguments)
	return args.Get(0).(pgconn.CommandTag), args.Error(1)
}

func (m *MockTx) Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
	mockArgs := m.Called(ctx, sql, args)
	return mockArgs.Get(0).(pgx.Rows), mockArgs.Error(1)
}

func (m *MockTx) QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row {
	mockArgs := m.Called(ctx, sql, args)
	return mockArgs.Get(0).(pgx.Row)
}

func (m *MockTx) Conn() *pgx.Conn {
	args := m.Called()
	return args.Get(0).(*pgx.Conn)
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
	mockService := mocks.NewServiceInterface(t)
	mockPool := createMockPool()
	controller := NewChannelController(mockService, mockPool)

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
	mockService.On("SearchChannelsCount", mock.Anything, "%test%").Return(int64(2), nil)
	mockService.On("SearchChannels", mock.Anything, models.SearchChannelsParams{
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

	mockService.AssertExpectations(t)
}

func TestChannelController_SearchChannels_Unauthorized(t *testing.T) {
	// Setup
	mockService := mocks.NewServiceInterface(t)
	mockPool := createMockPool()
	controller := NewChannelController(mockService, mockPool)

	// Create test context without JWT claims
	c, rec := createTestContext("GET", "/channels/search?q=test", 0)

	// Execute
	err := controller.SearchChannels(c)

	// Assert
	assert.NoError(t, err) // The controller handles the error internally
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	// Parse response as new error format
	var response apierrors.ErrorResponse
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response.Error.Message, "Authorization information is missing")
}

func TestChannelController_SearchChannels_MissingQuery(t *testing.T) {
	// Setup
	mockService := mocks.NewServiceInterface(t)
	mockPool := createMockPool()
	controller := NewChannelController(mockService, mockPool)

	// Create test context without query parameter
	c, rec := createTestContext("GET", "/channels/search", 123)

	// Execute
	err := controller.SearchChannels(c)

	// Assert
	assert.NoError(t, err) // The controller handles the error internally
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	// Parse response as new error format
	var response apierrors.ErrorResponse
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response.Error.Message, "Search query parameter 'q' is required")
}

func TestChannelController_SearchChannels_DatabaseError(t *testing.T) {
	// Setup
	mockService := mocks.NewServiceInterface(t)
	mockPool := createMockPool()
	controller := NewChannelController(mockService, mockPool)

	// Setup mock to return error for count query
	mockService.On("SearchChannelsCount", mock.Anything, "%test%").Return(int64(0), fmt.Errorf("database error"))

	// The SearchChannels method should not be called when count fails, but if tracing continues,
	// we need to handle it gracefully
	mockService.On("SearchChannels", mock.Anything, mock.AnythingOfType("models.SearchChannelsParams")).
		Return([]models.SearchChannelsRow{}, fmt.Errorf("database error")).Maybe()

	// Create test context
	c, rec := createTestContext("GET", "/channels/search?q=test", 123)

	// Execute
	err := controller.SearchChannels(c)

	// Assert
	assert.NoError(t, err) // The controller handles the error internally
	assert.Equal(t, http.StatusInternalServerError, rec.Code)

	// Due to tracing integration issues, multiple responses may be written
	// Extract the first JSON response which should be the error
	responseBody := rec.Body.String()
	lines := strings.Split(strings.TrimSpace(responseBody), "\n")

	// Parse the first response (should be the error response)
	var response apierrors.ErrorResponse
	err = json.Unmarshal([]byte(lines[0]), &response)
	assert.NoError(t, err)
	assert.Contains(t, response.Error.Message, "An error occurred while processing your request")

	mockService.AssertExpectations(t)
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
	mockService := mocks.NewServiceInterface(t)
	mockPool := createMockPool()
	controller := NewChannelController(mockService, mockPool)

	// Mock data
	channelID := int32(1)
	userID := int32(123)
	requestBody := `{"description": "Updated description", "url": "https://example.com/updated"}`

	// Setup mocks
	mockService.On("CheckChannelExists", mock.Anything, channelID).Return(models.CheckChannelExistsRow{
		ID:   channelID,
		Name: "#test",
	}, nil)

	mockService.On("GetChannelUserAccess", mock.Anything, channelID, userID).Return(models.GetChannelUserAccessRow{
		Access:    500,
		UserID:    userID,
		ChannelID: channelID,
	}, nil)

	mockService.On("UpdateChannelSettings", mock.Anything, models.UpdateChannelSettingsParams{
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

	mockService.AssertExpectations(t)
}

func TestChannelController_UpdateChannelSettings_PartialUpdate(t *testing.T) {
	// Setup
	mockService := mocks.NewServiceInterface(t)
	mockPool := createMockPool()
	controller := NewChannelController(mockService, mockPool)

	// Mock data - only updating description
	channelID := int32(1)
	userID := int32(123)
	requestBody := `{"description": "New description only"}`

	// Setup mocks
	mockService.On("CheckChannelExists", mock.Anything, channelID).Return(models.CheckChannelExistsRow{
		ID:   channelID,
		Name: "#test",
	}, nil)

	mockService.On("GetChannelUserAccess", mock.Anything, channelID, userID).Return(models.GetChannelUserAccessRow{
		Access:    500,
		UserID:    userID,
		ChannelID: channelID,
	}, nil)

	// Need to get current channel data to preserve URL
	mockService.On("GetChannelByID", mock.Anything, channelID).Return(models.GetChannelByIDRow{
		ID:          channelID,
		Name:        "#test",
		Description: pgtype.Text{String: "Old description", Valid: true},
		Url:         pgtype.Text{String: "https://example.com/old", Valid: true},
		CreatedAt:   pgtype.Int4{Int32: 1640995200, Valid: true},
		MemberCount: 42,
	}, nil)

	mockService.On("UpdateChannelSettings", mock.Anything, models.UpdateChannelSettingsParams{
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

	mockService.AssertExpectations(t)
}

func TestChannelController_UpdateChannelSettings_Unauthorized(t *testing.T) {
	// Setup
	mockService := mocks.NewServiceInterface(t)
	mockPool := createMockPool()
	controller := NewChannelController(mockService, mockPool)

	// Create test context without JWT claims
	c, rec := createTestContextWithBody("PUT", "/channels/1", 0, `{"description": "test"}`)
	c.SetParamNames("id")
	c.SetParamValues("1")

	// Execute
	err := controller.UpdateChannelSettings(c)

	// Assert
	assert.NoError(t, err) // The controller handles the error internally
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	// Parse response as new error format
	var response apierrors.ErrorResponse
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response.Error.Message, "Authorization information is missing")
}

func TestChannelController_UpdateChannelSettings_InvalidChannelID(t *testing.T) {
	// Setup
	mockService := mocks.NewServiceInterface(t)
	mockPool := createMockPool()
	controller := NewChannelController(mockService, mockPool)

	// Create test context with invalid channel ID
	c, rec := createTestContextWithBody("PUT", "/channels/invalid", 123, `{"description": "test"}`)
	c.SetParamNames("id")
	c.SetParamValues("invalid")

	// Execute
	err := controller.UpdateChannelSettings(c)

	// Assert
	assert.NoError(t, err) // The controller handles the error internally
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	// Parse response as new error format
	var response apierrors.ErrorResponse
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response.Error.Message, "Invalid channel ID")
}

func TestChannelController_UpdateChannelSettings_ChannelNotFound(t *testing.T) {
	// Setup
	mockService := mocks.NewServiceInterface(t)
	mockPool := createMockPool()
	controller := NewChannelController(mockService, mockPool)

	channelID := int32(999)
	requestBody := `{"description": "test"}`

	// Setup mock - channel doesn't exist
	mockService.On("CheckChannelExists", mock.Anything, channelID).
		Return(models.CheckChannelExistsRow{}, fmt.Errorf("no rows found"))

	// Create test context
	c, rec := createTestContextWithBody("PUT", "/channels/999", 123, requestBody)
	c.SetParamNames("id")
	c.SetParamValues("999")

	// Execute
	err := controller.UpdateChannelSettings(c)

	// Assert - controller now handles errors internally
	assert.NoError(t, err)
	assert.Equal(t, http.StatusNotFound, rec.Code)

	// Parse response as new error format
	var response apierrors.ErrorResponse
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response.Error.Message, "not found")

	mockService.AssertExpectations(t)
}

func TestChannelController_UpdateChannelSettings_InsufficientAccess(t *testing.T) {
	// Setup
	mockService := mocks.NewServiceInterface(t)
	mockPool := createMockPool()
	controller := NewChannelController(mockService, mockPool)

	channelID := int32(1)
	userID := int32(123)
	requestBody := `{"description": "test"}`

	// Setup mocks
	mockService.On("CheckChannelExists", mock.Anything, channelID).Return(models.CheckChannelExistsRow{
		ID:   channelID,
		Name: "#test",
	}, nil)

	// User has insufficient access (< 500)
	mockService.On("GetChannelUserAccess", mock.Anything, channelID, userID).Return(models.GetChannelUserAccessRow{
		Access:    100, // Too low
		UserID:    userID,
		ChannelID: channelID,
	}, nil)

	// Create test context
	c, rec := createTestContextWithBody("PUT", "/channels/1", userID, requestBody)
	c.SetParamNames("id")
	c.SetParamValues("1")

	// Execute
	err := controller.UpdateChannelSettings(c)

	// Assert - controller now handles errors internally
	assert.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, rec.Code)

	// Parse response as new error format
	var response apierrors.ErrorResponse
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response.Error.Message, "Insufficient permissions")

	mockService.AssertExpectations(t)
}

func TestChannelController_UpdateChannelSettings_ValidationErrors(t *testing.T) {
	// Setup
	mockService := mocks.NewServiceInterface(t)
	mockPool := createMockPool()
	controller := NewChannelController(mockService, mockPool)

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
			c, rec := createTestContextWithBody("PUT", "/channels/1", 123, tc.requestBody)
			c.SetParamNames("id")
			c.SetParamValues("1")

			// Execute
			err := controller.UpdateChannelSettings(c)

			// Assert - controller now handles errors internally
			assert.NoError(t, err)
			assert.Equal(t, http.StatusBadRequest, rec.Code)

			// Parse response as new error format
			var response apierrors.ErrorResponse
			err = json.Unmarshal(rec.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Contains(t, strings.ToLower(response.Error.Message), tc.expectError)
		})
	}
}

func TestChannelController_GetChannelSettings_Success(t *testing.T) {
	// Setup
	mockService := mocks.NewServiceInterface(t)
	mockPool := createMockPool()
	controller := NewChannelController(mockService, mockPool)

	// Mock data
	channelID := int32(1)
	userID := int32(123)

	// Setup mocks
	mockService.On("GetChannelDetails", mock.Anything, channelID).Return(models.GetChannelDetailsRow{
		ID:          channelID,
		Name:        "#test",
		Description: pgtype.Text{String: "Test channel description", Valid: true},
		Url:         pgtype.Text{String: "https://example.com", Valid: true},
		CreatedAt:   pgtype.Int4{Int32: 1640995200, Valid: true},
		LastUpdated: 1640995300,
		MemberCount: 42,
	}, nil)

	mockService.On("GetChannelUserAccess", mock.Anything, channelID, userID).Return(models.GetChannelUserAccessRow{
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

	mockService.AssertExpectations(t)
}

func TestChannelController_GetChannelSettings_WithoutUpdatedTime(t *testing.T) {
	// Setup
	mockService := mocks.NewServiceInterface(t)
	mockPool := createMockPool()
	controller := NewChannelController(mockService, mockPool)

	// Mock data
	channelID := int32(1)
	userID := int32(123)

	// Setup mocks - channel without update timestamp
	mockService.On("GetChannelDetails", mock.Anything, channelID).Return(models.GetChannelDetailsRow{
		ID:          channelID,
		Name:        "#test",
		Description: pgtype.Text{String: "Test channel", Valid: true},
		Url:         pgtype.Text{Valid: false}, // No URL
		CreatedAt:   pgtype.Int4{Int32: 1640995200, Valid: true},
		LastUpdated: 0, // No update timestamp
		MemberCount: 10,
	}, nil)

	mockService.On("GetChannelUserAccess", mock.Anything, channelID, userID).Return(models.GetChannelUserAccessRow{
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

	mockService.AssertExpectations(t)
}

func TestChannelController_GetChannelSettings_InvalidChannelID(t *testing.T) {
	// Setup
	mockService := mocks.NewServiceInterface(t)
	mockPool := createMockPool()
	controller := NewChannelController(mockService, mockPool)

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
			c, rec := createTestContext("GET", "/channels/"+tc.channelID, 123)
			c.SetParamNames("id")
			c.SetParamValues(tc.channelID)

			// Execute
			err := controller.GetChannelSettings(c)

			// Assert - controller now handles errors internally
			assert.NoError(t, err)
			assert.Equal(t, http.StatusBadRequest, rec.Code)

			// Parse response as new error format
			var response apierrors.ErrorResponse
			err = json.Unmarshal(rec.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Contains(t, response.Error.Message, "Invalid channel ID")
		})
	}
}

func TestChannelController_GetChannelSettings_ChannelNotFound(t *testing.T) {
	// Setup
	mockService := mocks.NewServiceInterface(t)
	mockPool := createMockPool()
	controller := NewChannelController(mockService, mockPool)

	channelID := int32(999)

	// Setup mock - channel doesn't exist
	mockService.On("GetChannelDetails", mock.Anything, channelID).
		Return(models.GetChannelDetailsRow{}, fmt.Errorf("no rows found"))

	// Create test context
	c, rec := createTestContext("GET", "/channels/999", 123)
	c.SetParamNames("id")
	c.SetParamValues("999")

	// Execute
	err := controller.GetChannelSettings(c)

	// Assert - controller now handles errors internally
	assert.NoError(t, err)
	assert.Equal(t, http.StatusNotFound, rec.Code)

	// Parse response as new error format
	var response apierrors.ErrorResponse
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response.Error.Message, "not found")

	mockService.AssertExpectations(t)
}

func TestChannelController_GetChannelSettings_Unauthorized(t *testing.T) {
	// Setup
	mockService := mocks.NewServiceInterface(t)
	mockPool := createMockPool()
	controller := NewChannelController(mockService, mockPool)

	// Create test context without JWT claims
	c, rec := createTestContext("GET", "/channels/1", 0)
	c.SetParamNames("id")
	c.SetParamValues("1")

	// Execute
	err := controller.GetChannelSettings(c)

	// Assert - controller now handles errors internally
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	// Parse response as new error format
	var response apierrors.ErrorResponse
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response.Error.Message, "Authorization information is missing")
}

func TestChannelController_GetChannelSettings_InsufficientAccess(t *testing.T) {
	// Setup
	mockService := mocks.NewServiceInterface(t)
	mockPool := createMockPool()
	controller := NewChannelController(mockService, mockPool)

	channelID := int32(1)
	userID := int32(123)

	// Setup mocks
	mockService.On("GetChannelDetails", mock.Anything, channelID).Return(models.GetChannelDetailsRow{
		ID:   channelID,
		Name: "#test",
	}, nil)

	// User has insufficient access (< 100)
	mockService.On("GetChannelUserAccess", mock.Anything, channelID, userID).Return(models.GetChannelUserAccessRow{
		Access:    50, // Too low for viewing
		UserID:    userID,
		ChannelID: channelID,
	}, nil)

	// Create test context
	c, rec := createTestContext("GET", "/channels/1", userID)
	c.SetParamNames("id")
	c.SetParamValues("1")

	// Execute
	err := controller.GetChannelSettings(c)

	// Assert - controller now handles errors internally
	assert.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, rec.Code)

	// Parse response as new error format
	var response apierrors.ErrorResponse
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response.Error.Message, "Insufficient permissions")

	mockService.AssertExpectations(t)
}

func TestChannelController_GetChannelSettings_UserNotInChannel(t *testing.T) {
	// Setup
	mockService := mocks.NewServiceInterface(t)
	mockPool := createMockPool()
	controller := NewChannelController(mockService, mockPool)

	channelID := int32(1)
	userID := int32(123)

	// Setup mocks
	mockService.On("GetChannelDetails", mock.Anything, channelID).Return(models.GetChannelDetailsRow{
		ID:   channelID,
		Name: "#test",
	}, nil)

	// User not found in channel
	mockService.On("GetChannelUserAccess", mock.Anything, channelID, userID).
		Return(models.GetChannelUserAccessRow{}, fmt.Errorf("no rows found"))

	// Create test context
	c, rec := createTestContext("GET", "/channels/1", userID)
	c.SetParamNames("id")
	c.SetParamValues("1")

	// Execute
	err := controller.GetChannelSettings(c)

	// Assert - controller now handles errors internally
	assert.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, rec.Code)

	// Parse response as new error format
	var response apierrors.ErrorResponse
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response.Error.Message, "Insufficient permissions")

	mockService.AssertExpectations(t)
}

func TestAddChannelMember_Success(t *testing.T) {
	// Setup
	e := echo.New()
	e.Validator = helper.NewValidator()
	mockService := mocks.NewServiceInterface(t)
	mockPool := createMockPool()
	controller := NewChannelController(mockService, mockPool)

	// Test data
	channelID := int32(1)
	userID := int32(2)
	accessLevel := int32(200)
	requesterUserID := int32(3)
	requesterAccess := int32(450) // Changed to meet new requirement of 400+

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
	mockService := mocks.NewServiceInterface(t)
	mockPool := createMockPool()
	controller := NewChannelController(mockService, mockPool)

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

	// Assert - controller now handles errors internally
	assert.NoError(t, err)
	assert.Equal(t, http.StatusNotFound, rec.Code)

	// Parse the error response
	var errorResp apierrors.ErrorResponse
	decodeErr := json.Unmarshal(rec.Body.Bytes(), &errorResp)
	assert.NoError(t, decodeErr)
	assert.Equal(t, "Channel not found", errorResp.Error.Message)

	mockService.AssertExpectations(t)
}

func TestAddChannelMember_InsufficientPermissions(t *testing.T) {
	// Setup
	e := echo.New()
	e.Validator = helper.NewValidator()
	mockService := mocks.NewServiceInterface(t)
	mockPool := createMockPool()
	controller := NewChannelController(mockService, mockPool)

	// Test data
	channelID := int32(1)
	userID := int32(2)
	requesterUserID := int32(3)
	requesterAccess := int32(50) // Below minimum required (400)

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

	// Assert - controller now handles errors internally
	assert.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, rec.Code)

	// Parse the error response
	var errorResp apierrors.ErrorResponse
	decodeErr := json.Unmarshal(rec.Body.Bytes(), &errorResp)
	assert.NoError(t, decodeErr)
	assert.Equal(t, "Insufficient permissions to add members", errorResp.Error.Message)

	mockService.AssertExpectations(t)
}

func TestAddChannelMember_CannotAddHigherLevel(t *testing.T) {
	// Setup
	e := echo.New()
	e.Validator = helper.NewValidator()
	mockService := mocks.NewServiceInterface(t)
	mockPool := createMockPool()
	controller := NewChannelController(mockService, mockPool)

	// Test data
	channelID := int32(1)
	userID := int32(2)
	requesterUserID := int32(3)
	requesterAccess := int32(450) // Changed to meet new requirement of 400+
	requestedAccessLevel := 460   // Higher than requester's level

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

	// Assert - controller now handles errors internally
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)

	// Parse the error response
	var errorResp apierrors.ErrorResponse
	decodeErr := json.Unmarshal(rec.Body.Bytes(), &errorResp)
	assert.NoError(t, decodeErr)
	assert.Equal(t, "Cannot add user with access level higher than or equal to your own", errorResp.Error.Message)

	mockService.AssertExpectations(t)
}

func TestAddChannelMember_UserAlreadyExists(t *testing.T) {
	// Setup
	e := echo.New()
	e.Validator = helper.NewValidator()
	mockService := mocks.NewServiceInterface(t)
	mockPool := createMockPool()
	controller := NewChannelController(mockService, mockPool)

	// Test data
	channelID := int32(1)
	userID := int32(2)
	requesterUserID := int32(3)
	requesterAccess := int32(450) // Changed to meet new requirement of 400+

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

	// Assert - controller now handles errors internally
	assert.NoError(t, err)
	assert.Equal(t, http.StatusConflict, rec.Code)

	// Parse the error response
	var errorResp apierrors.ErrorResponse
	decodeErr := json.Unmarshal(rec.Body.Bytes(), &errorResp)
	assert.NoError(t, decodeErr)
	assert.Equal(t, "User is already a member of this channel", errorResp.Error.Message)

	mockService.AssertExpectations(t)
}

func TestRemoveChannelMember_Success(t *testing.T) {
	// Setup
	e := echo.New()
	e.Validator = helper.NewValidator()
	mockService := mocks.NewServiceInterface(t)
	mockPool := createMockPool()
	controller := NewChannelController(mockService, mockPool)

	// Test data
	channelID := int32(1)
	targetUserID := int32(2)
	requesterUserID := int32(3)
	requesterAccess := int32(450) // Changed to meet new requirement of 400+
	targetAccess := int32(200)    // Lower than requester

	// Mock JWT claims
	claims := &helper.JwtClaims{
		UserID:   requesterUserID,
		Username: "testuser",
	}

	// Request body
	reqBody := RemoveMemberRequest{
		UserID: int64(targetUserID),
	}
	reqJSON, _ := json.Marshal(reqBody)

	// Create request
	req := httptest.NewRequest(http.MethodDelete, "/channels/1/members", bytes.NewReader(reqJSON))
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
	mockService.On("GetChannelUserAccess", mock.Anything, channelID, targetUserID).
		Return(models.GetChannelUserAccessRow{
			Access:    targetAccess,
			UserID:    targetUserID,
			ChannelID: channelID,
		}, nil)
	mockService.On("RemoveChannelMember", mock.Anything, models.RemoveChannelMemberParams{
		ChannelID:   channelID,
		UserID:      targetUserID,
		LastModifBy: db.NewString("testuser"),
	}).Return(models.RemoveChannelMemberRow{
		ChannelID: channelID,
		UserID:    targetUserID,
		Access:    targetAccess,
		LastModif: pgtype.Int4{Int32: 1640995200, Valid: true},
	}, nil)

	// Execute
	err := controller.RemoveChannelMember(c)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	// Parse response
	var response RemoveMemberResponse
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	assert.NoError(t, err)

	// Verify response
	assert.Equal(t, channelID, response.ChannelID)
	assert.Equal(t, int64(targetUserID), response.UserID)
	assert.Equal(t, int32(1640995200), response.RemovedAt)
	assert.Equal(t, "Member removed successfully", response.Message)

	mockService.AssertExpectations(t)
}

func TestRemoveChannelMember_SelfRemoval_Success(t *testing.T) {
	// Setup
	e := echo.New()
	e.Validator = helper.NewValidator()
	mockService := mocks.NewServiceInterface(t)
	mockPool := createMockPool()
	controller := NewChannelController(mockService, mockPool)

	// Test data - user removing themselves
	channelID := int32(1)
	userID := int32(2)
	userAccess := int32(200) // Not an owner (< 500)

	// Mock JWT claims
	claims := &helper.JwtClaims{
		UserID:   userID,
		Username: "testuser",
	}

	// Request body
	reqBody := RemoveMemberRequest{
		UserID: int64(userID), // Same as requester
	}
	reqJSON, _ := json.Marshal(reqBody)

	// Create request
	req := httptest.NewRequest(http.MethodDelete, "/channels/1/members", bytes.NewReader(reqJSON))
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
	mockService.On("GetChannelUserAccess", mock.Anything, channelID, userID).
		Return(models.GetChannelUserAccessRow{
			Access:    userAccess,
			UserID:    userID,
			ChannelID: channelID,
		}, nil).Twice() // Called for both requester and target (same user)
	mockService.On("RemoveChannelMember", mock.Anything, models.RemoveChannelMemberParams{
		ChannelID:   channelID,
		UserID:      userID,
		LastModifBy: db.NewString("testuser"),
	}).Return(models.RemoveChannelMemberRow{
		ChannelID: channelID,
		UserID:    userID,
		Access:    userAccess,
		LastModif: pgtype.Int4{Int32: 1640995200, Valid: true},
	}, nil)

	// Execute
	err := controller.RemoveChannelMember(c)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	mockService.AssertExpectations(t)
}

func TestRemoveChannelMember_CannotRemoveLastOwner(t *testing.T) {
	// Setup
	e := echo.New()
	e.Validator = helper.NewValidator()
	mockService := mocks.NewServiceInterface(t)
	mockPool := createMockPool()
	controller := NewChannelController(mockService, mockPool)

	// Test data
	channelID := int32(1)
	ownerUserID := int32(2)
	ownerAccess := int32(500) // Owner level

	// Mock JWT claims
	claims := &helper.JwtClaims{
		UserID:   ownerUserID,
		Username: "owner",
	}

	// Request body - owner trying to remove themselves
	reqBody := RemoveMemberRequest{
		UserID: int64(ownerUserID),
	}
	reqJSON, _ := json.Marshal(reqBody)

	// Create request
	req := httptest.NewRequest(http.MethodDelete, "/channels/1/members", bytes.NewReader(reqJSON))
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
	mockService.On("GetChannelUserAccess", mock.Anything, channelID, ownerUserID).
		Return(models.GetChannelUserAccessRow{
			Access:    ownerAccess,
			UserID:    ownerUserID,
			ChannelID: channelID,
		}, nil).Twice()
	mockService.On("CountChannelOwners", mock.Anything, channelID).Return(int64(1), nil) // Only one owner

	// Execute
	err := controller.RemoveChannelMember(c)

	// Assert - controller now handles errors internally
	assert.NoError(t, err)
	assert.Equal(t, http.StatusConflict, rec.Code)

	// Parse the error response
	var errorResp apierrors.ErrorResponse
	decodeErr := json.Unmarshal(rec.Body.Bytes(), &errorResp)
	assert.NoError(t, decodeErr)
	assert.Equal(t, "Cannot remove the last channel owner", errorResp.Error.Message)

	mockService.AssertExpectations(t)
}

func TestRemoveChannelMember_CannotRemoveHigherLevel(t *testing.T) {
	// Setup
	e := echo.New()
	e.Validator = helper.NewValidator()
	mockService := mocks.NewServiceInterface(t)
	mockPool := createMockPool()
	controller := NewChannelController(mockService, mockPool)

	// Test data
	channelID := int32(1)
	targetUserID := int32(2)
	requesterUserID := int32(3)
	requesterAccess := int32(450) // Changed to meet new requirement of 400+
	targetAccess := int32(460)    // Higher than requester

	// Mock JWT claims
	claims := &helper.JwtClaims{
		UserID:   requesterUserID,
		Username: "testuser",
	}

	// Request body
	reqBody := RemoveMemberRequest{
		UserID: int64(targetUserID),
	}
	reqJSON, _ := json.Marshal(reqBody)

	// Create request
	req := httptest.NewRequest(http.MethodDelete, "/channels/1/members", bytes.NewReader(reqJSON))
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
	mockService.On("GetChannelUserAccess", mock.Anything, channelID, targetUserID).
		Return(models.GetChannelUserAccessRow{
			Access:    targetAccess,
			UserID:    targetUserID,
			ChannelID: channelID,
		}, nil)

	// Execute
	err := controller.RemoveChannelMember(c)

	// Assert - controller now handles errors internally
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)

	// Parse the error response
	var errorResp apierrors.ErrorResponse
	decodeErr := json.Unmarshal(rec.Body.Bytes(), &errorResp)
	assert.NoError(t, decodeErr)
	assert.Equal(t, "Cannot remove user with access level higher than or equal to your own", errorResp.Error.Message)

	mockService.AssertExpectations(t)
}

func TestRemoveChannelMember_ProtectedChannel(t *testing.T) {
	// Setup
	e := echo.New()
	e.Validator = helper.NewValidator()
	mockService := mocks.NewServiceInterface(t)
	mockPool := createMockPool()
	controller := NewChannelController(mockService, mockPool)

	// Test data - using the special "*" channel
	channelID := int32(1)
	userID := int32(2)

	// Mock JWT claims
	claims := &helper.JwtClaims{
		UserID:   int32(3),
		Username: "testuser",
	}

	// Request body
	reqBody := RemoveMemberRequest{
		UserID: int64(userID),
	}
	reqJSON, _ := json.Marshal(reqBody)

	// Create request
	req := httptest.NewRequest(http.MethodDelete, "/channels/1/members", bytes.NewReader(reqJSON))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues("1")

	// Set JWT token in context
	token := &jwt.Token{Claims: claims}
	c.Set("user", token)

	// Mock expectations - return the special "*" channel
	mockService.On("GetChannelByName", mock.Anything, "*").Return(models.GetChannelByNameRow{
		ID:   channelID,
		Name: "*",
	}, nil)

	// Execute
	err := controller.RemoveChannelMember(c)

	// Assert - controller now handles errors internally
	assert.NoError(t, err)
	assert.Equal(t, http.StatusNotFound, rec.Code)

	// Parse the error response
	var errorResp apierrors.ErrorResponse
	decodeErr := json.Unmarshal(rec.Body.Bytes(), &errorResp)
	assert.NoError(t, decodeErr)
	assert.Equal(t, "Channel not found", errorResp.Error.Message)

	mockService.AssertExpectations(t)
}

func TestRemoveChannelMember_UserNotInChannel(t *testing.T) {
	// Setup
	e := echo.New()
	e.Validator = helper.NewValidator()
	mockService := mocks.NewServiceInterface(t)
	mockPool := createMockPool()
	controller := NewChannelController(mockService, mockPool)

	// Test data
	channelID := int32(1)
	targetUserID := int32(2)
	requesterUserID := int32(3)
	requesterAccess := int32(450) // Changed to meet new requirement of 400+

	// Mock JWT claims
	claims := &helper.JwtClaims{
		UserID:   requesterUserID,
		Username: "testuser",
	}

	// Request body
	reqBody := RemoveMemberRequest{
		UserID: int64(targetUserID),
	}
	reqJSON, _ := json.Marshal(reqBody)

	// Create request
	req := httptest.NewRequest(http.MethodDelete, "/channels/1/members", bytes.NewReader(reqJSON))
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
	// Target user not found in channel
	mockService.On("GetChannelUserAccess", mock.Anything, channelID, targetUserID).
		Return(models.GetChannelUserAccessRow{}, assert.AnError)

	// Execute
	err := controller.RemoveChannelMember(c)

	// Assert - controller now handles errors internally
	assert.NoError(t, err)
	assert.Equal(t, http.StatusNotFound, rec.Code)

	// Parse the error response
	var errorResp apierrors.ErrorResponse
	decodeErr := json.Unmarshal(rec.Body.Bytes(), &errorResp)
	assert.NoError(t, decodeErr)
	assert.Equal(t, "User is not a member of this channel", errorResp.Error.Message)

	mockService.AssertExpectations(t)
}

func TestRemoveChannelMember_Unauthorized(t *testing.T) {
	// Setup
	e := echo.New()
	e.Validator = helper.NewValidator()
	mockService := mocks.NewServiceInterface(t)
	mockPool := createMockPool()
	controller := NewChannelController(mockService, mockPool)

	// Request body
	reqBody := RemoveMemberRequest{
		UserID: 123,
	}
	reqJSON, _ := json.Marshal(reqBody)

	// Create request without JWT token
	req := httptest.NewRequest(http.MethodDelete, "/channels/1/members", bytes.NewReader(reqJSON))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues("1")

	// Execute without setting user context
	err := controller.RemoveChannelMember(c)

	// Assert - controller now handles errors internally
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	// Parse the error response
	var errorResp apierrors.ErrorResponse
	decodeErr := json.Unmarshal(rec.Body.Bytes(), &errorResp)
	assert.NoError(t, decodeErr)
	assert.Contains(t, errorResp.Error.Message, "Authorization information is missing")

	mockService.AssertExpectations(t)
}

func TestRemoveChannelMember_InsufficientPermissions(t *testing.T) {
	// Setup
	e := echo.New()
	e.Validator = helper.NewValidator()
	mockService := mocks.NewServiceInterface(t)
	mockPool := createMockPool()
	controller := NewChannelController(mockService, mockPool)

	// Test data
	channelID := int32(1)
	requesterUserID := int32(3)
	requesterAccess := int32(50) // Below minimum required (400)

	// Mock JWT claims
	claims := &helper.JwtClaims{
		UserID:   requesterUserID,
		Username: "testuser",
	}

	// Request body
	reqBody := RemoveMemberRequest{
		UserID: 123,
	}
	reqJSON, _ := json.Marshal(reqBody)

	// Create request
	req := httptest.NewRequest(http.MethodDelete, "/channels/1/members", bytes.NewReader(reqJSON))
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
	err := controller.RemoveChannelMember(c)

	// Assert - controller now handles errors internally
	assert.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, rec.Code)

	// Parse the error response
	var errorResp apierrors.ErrorResponse
	decodeErr := json.Unmarshal(rec.Body.Bytes(), &errorResp)
	assert.NoError(t, decodeErr)
	assert.Equal(t, "Insufficient permissions to remove members", errorResp.Error.Message)

	mockService.AssertExpectations(t)
}

// Channel Registration Tests

func TestChannelController_RegisterChannel_Success(t *testing.T) {
	mockService := mocks.NewServiceInterface(t)
	mockPool := &MockPool{}
	mockTx := &MockTx{}
	controller := NewChannelController(mockService, mockPool)

	config.ServiceChannelRegEnabled.Set(true)
	config.ServiceChannelRegMinDaysBeforeSupport.Set(0) // Allow any supporter age for testing
	config.ServiceChannelRegRequiredSupporters.Set(2)
	config.ServiceChannelRegIrcIdleHours.Set(168)
	config.ServiceChannelRegMinDaysBeforeSupport.Set(0) // Allow any supporter age for testing

	// Setup all validation mocks
	setupBasicUserValidation(mockService)
	mockService.On("CheckChannelNameExists", mock.Anything, "#test").Return(models.CheckChannelNameExistsRow{}, fmt.Errorf("not found"))
	setupSupporterValidation(mockService, []string{"user1", "user2"})

	// Setup transaction mocks
	mockPool.On("Begin", mock.Anything).Return(mockTx, nil)
	mockTx.On("Rollback", mock.Anything).Return(nil)
	mockTx.On("Commit", mock.Anything).Return(nil)

	qtx := mocks.NewServiceInterface(t)
	mockService.On("WithTx", mockTx).Return(qtx)
	setupSuccessfulTransactionMocks(qtx)

	reqBody := `{"channel_name": "#test", "description": "test", "supporters": ["user1", "user2"]}`
	c, rec := createTestContextWithBody("POST", "/channels", 123, reqBody)

	err := controller.RegisterChannel(c)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusCreated, rec.Code)

	var response ChannelRegistrationResponse
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "success", response.Status)
	assert.Equal(t, "#test", response.Data.ChannelName)
	assert.Equal(t, "pending", response.Data.Status)

	mockService.AssertExpectations(t)
	mockPool.AssertExpectations(t)
	mockTx.AssertExpectations(t)
	qtx.AssertExpectations(t)
}

func TestChannelController_RegisterChannel_Unauthorized(t *testing.T) {
	mockService := mocks.NewServiceInterface(t)
	mockPool := &MockPool{}
	controller := NewChannelController(mockService, mockPool)

	// Set configuration
	config.ServiceChannelRegEnabled.Set(true)
	config.ServiceChannelRegMinDaysBeforeSupport.Set(0) // Allow any supporter age for testing

	reqBody := `{"channel_name": "#test", "description": "test", "supporters": ["user1", "user2"]}`
	c, rec := createTestContextWithBody("POST", "/channels", 0, reqBody) // userID 0 = no auth

	err := controller.RegisterChannel(c)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestChannelController_RegisterChannel_RegistrationDisabled(t *testing.T) {
	mockService := mocks.NewServiceInterface(t)
	mockPool := &MockPool{}
	controller := NewChannelController(mockService, mockPool)

	// Disable channel registration
	config.ServiceChannelRegEnabled.Set(false)
	config.ServiceChannelRegMaxConcurrentSupports.Set(0) // Set to 0 for this test

	// Setup mocks for the validation flow that happens before registration disabled check
	// 1. ValidateChannelRegistrationWithAdminBypass (includes supporter validation)
	mockService.On("GetUser", mock.Anything, models.GetUserParams{ID: int32(123)}).Return(models.GetUserRow{
		ID:       123,
		Username: "testuser",
	}, nil)
	setupSupporterValidation(mockService, []string{"user1", "user2"})

	// 2. ValidateUserNoregStatusWithAdminBypass
	mockService.On("CheckUserNoregStatus", mock.Anything, "testuser").Return(false, nil)

	// 3. ValidateUserChannelLimitsWithAdminBypass (this is where registration disabled check happens)
	mockService.On("GetUserChannels", mock.Anything, int32(123)).Return([]models.GetUserChannelsRow{}, nil)

	reqBody := `{"channel_name": "#test", "description": "test", "supporters": ["user1", "user2"]}`
	c, rec := createTestContextWithBody("POST", "/channels", 123, reqBody)

	err := controller.RegisterChannel(c)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestChannelController_RegisterChannel_InvalidJSON(t *testing.T) {
	mockService := mocks.NewServiceInterface(t)
	mockPool := &MockPool{}
	controller := NewChannelController(mockService, mockPool)

	config.ServiceChannelRegEnabled.Set(true)
	config.ServiceChannelRegMinDaysBeforeSupport.Set(0) // Allow any supporter age for testing

	reqBody := `{"channel_name": "#test", "description": "test", "supporters": [}`
	c, rec := createTestContextWithBody("POST", "/channels", 123, reqBody)

	err := controller.RegisterChannel(c)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestChannelController_RegisterChannel_ValidationErrors(t *testing.T) {
	tests := []struct {
		name         string
		requestBody  string
		expectedCode int
		setupMocks   bool
	}{
		{
			name:         "Missing channel name",
			requestBody:  `{"description": "test", "supporters": ["user1", "user2"]}`,
			expectedCode: http.StatusBadRequest,
			setupMocks:   false,
		},
		{
			name:         "Channel name doesn't start with #",
			requestBody:  `{"channel_name": "test", "description": "test", "supporters": ["user1", "user2"]}`,
			expectedCode: http.StatusBadRequest,
			setupMocks:   false,
		},
		{
			name:         "Channel name with invalid characters",
			requestBody:  `{"channel_name": "#test channel", "description": "test", "supporters": ["user1", "user2"]}`,
			expectedCode: http.StatusBadRequest,
			setupMocks:   false, // Business logic validation fails early, no mocks needed
		},
		{
			name:         "Channel name with special characters",
			requestBody:  `{"channel_name": "#test*", "description": "test", "supporters": ["user1", "user2"]}`,
			expectedCode: http.StatusBadRequest,
			setupMocks:   false, // Business logic validation fails early, no mocks needed
		},
		{
			name:         "Missing supporters",
			requestBody:  `{"channel_name": "#test", "description": "test"}`,
			expectedCode: http.StatusBadRequest,
			setupMocks:   false,
		},
		{
			name:         "Empty supporters array",
			requestBody:  `{"channel_name": "#test", "description": "test", "supporters": []}`,
			expectedCode: http.StatusBadRequest,
			setupMocks:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := mocks.NewServiceInterface(t)
			mockPool := &MockPool{}
			controller := NewChannelController(mockService, mockPool)

			config.ServiceChannelRegEnabled.Set(true)
			config.ServiceChannelRegMinDaysBeforeSupport.Set(0) // Allow any supporter age for testing

			if tt.setupMocks {
				setupBasicUserValidation(mockService)
				mockService.On("CheckChannelNameExists", mock.Anything, mock.AnythingOfType("string")).Return(models.CheckChannelNameExistsRow{}, fmt.Errorf("not found"))
				setupSupporterValidation(mockService, []string{"user1", "user2"})

				// Add transaction mocks for tests that pass request validation
				mockTx := &MockTx{}
				mockPool.On("Begin", mock.Anything).Return(mockTx, nil)
				mockTx.On("Rollback", mock.Anything).Return(nil)

				// Mock the WithTx call
				qtx := mocks.NewServiceInterface(t)
				mockService.On("WithTx", mockTx).Return(qtx)
			}

			c, rec := createTestContextWithBody("POST", "/channels", 123, tt.requestBody)

			err := controller.RegisterChannel(c)
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedCode, rec.Code)

			mockService.AssertExpectations(t)
		})
	}
}

func TestChannelController_RegisterChannel_UserValidationErrors(t *testing.T) {
	tests := []struct {
		name         string
		setupMocks   func(*mocks.ServiceInterface)
		expectedCode int
	}{
		{
			name: "User has noreg status",
			setupMocks: func(mockService *mocks.ServiceInterface) {
				// Supporter validation happens first
				mockService.On("GetUser", mock.Anything, models.GetUserParams{ID: int32(123)}).Return(models.GetUserRow{
					ID:       123,
					Username: "testuser",
				}, nil)
				setupSupporterValidation(mockService, []string{"user1", "user2"})
				// Then NOREG check
				mockService.On("CheckUserNoregStatus", mock.Anything, "testuser").Return(true, nil)
			},
			expectedCode: http.StatusForbidden,
		},
		{
			name: "User has too many channels",
			setupMocks: func(mockService *mocks.ServiceInterface) {
				// Set config to disallow multiple channels
				config.ServiceChannelRegAllowMultiple.Set(false)

				// Supporter validation happens first
				mockService.On("GetUser", mock.Anything, models.GetUserParams{ID: int32(123)}).Return(models.GetUserRow{
					ID:       123,
					Username: "testuser",
				}, nil)
				setupSupporterValidation(mockService, []string{"user1", "user2"})
				// Then user validation
				mockService.On("CheckUserNoregStatus", mock.Anything, "testuser").Return(false, nil)
				mockService.On("GetUserChannels", mock.Anything, int32(123)).Return([]models.GetUserChannelsRow{
					{ChannelID: 1}, // 1 existing channel - this will trigger multiple channel restriction
				}, nil)
				// Note: GetUserChannelCount and GetUserChannelLimit won't be called because
				// the multiple channel restriction fails first
			},
			expectedCode: http.StatusConflict,
		},
		{
			name: "User has pending registrations",
			setupMocks: func(mockService *mocks.ServiceInterface) {
				// Supporter validation happens first
				mockService.On("GetUser", mock.Anything, models.GetUserParams{ID: int32(123)}).Return(models.GetUserRow{
					ID:       123,
					Username: "testuser",
				}, nil)
				setupSupporterValidation(mockService, []string{"user1", "user2"})
				// Then user validation
				mockService.On("CheckUserNoregStatus", mock.Anything, "testuser").Return(false, nil)
				mockService.On("GetUserChannels", mock.Anything, int32(123)).Return([]models.GetUserChannelsRow{}, nil)
				mockService.On("GetUserChannelCount", mock.Anything, int32(123)).Return(int64(0), nil)
				mockService.On("GetUserChannelLimit", mock.Anything, mock.MatchedBy(func(params models.GetUserChannelLimitParams) bool {
					return params.ID == 123
				})).Return(int32(5), nil)
				mockService.On("GetUserPendingRegistrations", mock.Anything, pgtype.Int4{Int32: 123, Valid: true}).Return(int64(1), nil)
			},
			expectedCode: http.StatusConflict,
		},
		{
			name: "User not active on IRC",
			setupMocks: func(mockService *mocks.ServiceInterface) {
				// Supporter validation happens first
				mockService.On("GetUser", mock.Anything, models.GetUserParams{ID: int32(123)}).Return(models.GetUserRow{
					ID:       123,
					Username: "testuser",
					LastSeen: pgtype.Int4{
						Int32: int32(time.Now().Unix() - 8*24*3600), // 8 days ago
						Valid: true,
					},
				}, nil)
				setupSupporterValidation(mockService, []string{"user1", "user2"})
				// Then user validation
				mockService.On("CheckUserNoregStatus", mock.Anything, "testuser").Return(false, nil)
				mockService.On("GetUserChannels", mock.Anything, int32(123)).Return([]models.GetUserChannelsRow{}, nil)
				mockService.On("GetUserChannelCount", mock.Anything, int32(123)).Return(int64(0), nil)
				mockService.On("GetUserChannelLimit", mock.Anything, mock.MatchedBy(func(params models.GetUserChannelLimitParams) bool {
					return params.ID == 123
				})).Return(int32(5), nil)
				mockService.On("GetUserPendingRegistrations", mock.Anything, pgtype.Int4{Int32: 123, Valid: true}).Return(int64(0), nil)

				// Channel name validation
				mockService.On("CheckChannelNameExists", mock.Anything, "#test").Return(models.CheckChannelNameExistsRow{}, fmt.Errorf("not found"))
			},
			expectedCode: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := mocks.NewServiceInterface(t)
			mockPool := &MockPool{}
			controller := NewChannelController(mockService, mockPool)

			config.ServiceChannelRegEnabled.Set(true)
			config.ServiceChannelRegMinDaysBeforeSupport.Set(0) // Allow any supporter age for testing
			config.ServiceChannelRegRequiredSupporters.Set(2)
			config.ServiceChannelRegIrcIdleHours.Set(168) // 7 days

			tt.setupMocks(mockService)

			reqBody := `{"channel_name": "#test", "description": "test", "supporters": ["user1", "user2"]}`
			c, rec := createTestContextWithBody("POST", "/channels", 123, reqBody)

			err := controller.RegisterChannel(c)
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedCode, rec.Code)

			mockService.AssertExpectations(t)
		})
	}
}

func TestChannelController_RegisterChannel_ChannelValidationErrors(t *testing.T) {
	tests := []struct {
		name         string
		channelName  string
		setupMocks   func(*mocks.ServiceInterface)
		expectedCode int
	}{
		{
			name:        "Channel already exists",
			channelName: "#existing",
			setupMocks: func(mockService *mocks.ServiceInterface) {
				// Supporter validation happens first
				mockService.On("GetUser", mock.Anything, models.GetUserParams{ID: int32(123)}).Return(models.GetUserRow{
					ID:       123,
					Username: "testuser",
				}, nil)
				setupSupporterValidation(mockService, []string{"user1", "user2"})
				// Then user validation passes
				mockService.On("CheckUserNoregStatus", mock.Anything, "testuser").Return(false, nil)
				mockService.On("GetUserChannels", mock.Anything, int32(123)).Return([]models.GetUserChannelsRow{}, nil)
				mockService.On("GetUserChannelCount", mock.Anything, int32(123)).Return(int64(0), nil)
				mockService.On("GetUserChannelLimit", mock.Anything, mock.MatchedBy(func(params models.GetUserChannelLimitParams) bool {
					return params.ID == 123
				})).Return(int32(5), nil)
				mockService.On("GetUserPendingRegistrations", mock.Anything, pgtype.Int4{Int32: 123, Valid: true}).Return(int64(0), nil)

				// Channel exists (validation stops here, so GetUserLastSeen won't be called)
				mockService.On("CheckChannelNameExists", mock.Anything, "#existing").Return(models.CheckChannelNameExistsRow{
					ID:   42,
					Name: "#existing",
				}, nil)
			},
			expectedCode: http.StatusConflict,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := mocks.NewServiceInterface(t)
			mockPool := &MockPool{}
			controller := NewChannelController(mockService, mockPool)

			config.ServiceChannelRegEnabled.Set(true)
			config.ServiceChannelRegMinDaysBeforeSupport.Set(0) // Allow any supporter age for testing
			config.ServiceChannelRegRequiredSupporters.Set(2)
			config.ServiceChannelRegIrcIdleHours.Set(168)

			tt.setupMocks(mockService)

			reqBody := fmt.Sprintf(`{"channel_name": "%s", "description": "test", "supporters": ["user1", "user2"]}`, tt.channelName)
			c, rec := createTestContextWithBody("POST", "/channels", 123, reqBody)

			err := controller.RegisterChannel(c)
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedCode, rec.Code)

			mockService.AssertExpectations(t)
		})
	}
}

func TestChannelController_RegisterChannel_SupporterValidationErrors(t *testing.T) {
	tests := []struct {
		name         string
		supporters   []string
		setupMocks   func(*mocks.ServiceInterface)
		expectedCode int
	}{
		{
			name:       "Insufficient supporters",
			supporters: []string{"user1"}, // Only 1, need 2
			setupMocks: func(mockService *mocks.ServiceInterface) {
				// The validation logic calls GetUserByID even for insufficient supporters
				// This seems to be due to the validation flow implementation details
				mockService.On("GetUser", mock.Anything, models.GetUserParams{ID: int32(123)}).Return(models.GetUserRow{
					ID:       123,
					Username: "testuser",
				}, nil).Maybe()
				// Validation fails at supporter count check, but GetUserByID is still called
			},
			expectedCode: http.StatusBadRequest,
		},
		{
			name:       "Self support not allowed",
			supporters: []string{"testuser", "user2"},
			setupMocks: func(mockService *mocks.ServiceInterface) {
				// Only need GetUserByID for supporter validation, which fails early
				mockService.On("GetUser", mock.Anything, models.GetUserParams{ID: int32(123)}).Return(models.GetUserRow{
					ID:       123,
					Username: "testuser",
				}, nil)
				// No other mocks needed - validation fails at self-support check
			},
			expectedCode: http.StatusUnprocessableEntity,
		},
		{
			name:       "Duplicate supporters",
			supporters: []string{"user1", "user1"},
			setupMocks: func(mockService *mocks.ServiceInterface) {
				// Only need GetUserByID for supporter validation, which fails early
				mockService.On("GetUser", mock.Anything, models.GetUserParams{ID: int32(123)}).Return(models.GetUserRow{
					ID:       123,
					Username: "testuser",
				}, nil)
				// No other mocks needed - validation fails at duplicate check
			},
			expectedCode: http.StatusBadRequest,
		},
		{
			name:       "Supporter not found",
			supporters: []string{"nonexistent", "user2"},
			setupMocks: func(mockService *mocks.ServiceInterface) {
				// Need GetUser for supporter validation
				mockService.On("GetUser", mock.Anything, models.GetUserParams{ID: int32(123)}).Return(models.GetUserRow{
					ID:       123,
					Username: "testuser",
				}, nil)

				// Mock the bulk supporter validation with only one valid supporter
				// The validation will fail because "nonexistent" won't be found
				supporterRows := []models.GetSupportersByUsernamesRow{
					{
						ID:           202,
						Username:     "user2",
						SignupTs:     pgtype.Int4{Int32: int32(time.Now().Unix() - 86400*365), Valid: true}, // 1 year old
						Flags:        0,
						Email:        pgtype.Text{String: "user2@example.com", Valid: true},
						IsOldEnough:  true,
						DaysOld:      365,
						HasFraudFlag: false,
					},
					// "nonexistent" is not included in the results, simulating user not found
				}
				mockService.On("GetSupportersByUsernames", mock.Anything, []string{"nonexistent", "user2"}, mock.AnythingOfType("int32")).Return(supporterRows, nil)

				// No need for NOREG and concurrent support checks - validation fails early when supporters are invalid
			},
			expectedCode: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := mocks.NewServiceInterface(t)
			mockPool := &MockPool{}
			controller := NewChannelController(mockService, mockPool)

			config.ServiceChannelRegEnabled.Set(true)
			config.ServiceChannelRegMinDaysBeforeSupport.Set(0) // Allow any supporter age for testing
			config.ServiceChannelRegRequiredSupporters.Set(2)
			config.ServiceChannelRegIrcIdleHours.Set(168)

			tt.setupMocks(mockService)

			supportersJSON, _ := json.Marshal(tt.supporters)
			reqBody := fmt.Sprintf(`{"channel_name": "#test", "description": "test", "supporters": %s}`, supportersJSON)
			c, rec := createTestContextWithBody("POST", "/channels", 123, reqBody)

			err := controller.RegisterChannel(c)
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedCode, rec.Code)

			mockService.AssertExpectations(t)
		})
	}
}

func TestChannelController_RegisterChannel_DatabaseErrors(t *testing.T) {
	tests := []struct {
		name         string
		setupMocks   func(*mocks.ServiceInterface, *MockPool, *MockTx)
		expectedCode int
	}{
		{
			name: "Transaction begin fails",
			setupMocks: func(mockService *mocks.ServiceInterface, mockPool *MockPool, _ *MockTx) {
				setupBasicUserValidation(mockService)
				mockService.On("CheckChannelNameExists", mock.Anything, "#test").Return(models.CheckChannelNameExistsRow{}, fmt.Errorf("not found"))
				setupSupporterValidation(mockService, []string{"user1", "user2"})

				mockPool.On("Begin", mock.Anything).Return(nil, fmt.Errorf("connection failed"))
			},
			expectedCode: http.StatusInternalServerError,
		},
		{
			name: "Transaction commit fails",
			setupMocks: func(mockService *mocks.ServiceInterface, mockPool *MockPool, mockTx *MockTx) {
				setupBasicUserValidation(mockService)
				mockService.On("CheckChannelNameExists", mock.Anything, "#test").Return(models.CheckChannelNameExistsRow{}, fmt.Errorf("not found"))
				setupSupporterValidation(mockService, []string{"user1", "user2"})

				mockPool.On("Begin", mock.Anything).Return(mockTx, nil)
				mockTx.On("Rollback", mock.Anything).Return(nil)

				qtx := mocks.NewServiceInterface(t)
				mockService.On("WithTx", mockTx).Return(qtx)

				setupSuccessfulTransactionMocks(qtx)

				mockTx.On("Commit", mock.Anything).Return(fmt.Errorf("commit failed"))
			},
			expectedCode: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := mocks.NewServiceInterface(t)
			mockPool := &MockPool{}
			mockTx := &MockTx{}
			controller := NewChannelController(mockService, mockPool)

			config.ServiceChannelRegEnabled.Set(true)
			config.ServiceChannelRegMinDaysBeforeSupport.Set(0) // Allow any supporter age for testing
			config.ServiceChannelRegRequiredSupporters.Set(2)
			config.ServiceChannelRegIrcIdleHours.Set(168)

			tt.setupMocks(mockService, mockPool, mockTx)

			reqBody := `{"channel_name": "#test", "description": "test", "supporters": ["user1", "user2"]}`
			c, rec := createTestContextWithBody("POST", "/channels", 123, reqBody)

			err := controller.RegisterChannel(c)
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedCode, rec.Code)

			mockService.AssertExpectations(t)
			mockPool.AssertExpectations(t)
		})
	}
}

// Helper functions
func setupBasicUserValidation(mockService *mocks.ServiceInterface) {
	mockService.On("GetUser", mock.Anything, models.GetUserParams{ID: int32(123)}).Return(models.GetUserRow{
		ID:       123,
		Username: "testuser",
		LastSeen: pgtype.Int4{
			Int32: int32(time.Now().Unix() - 3600), // 1 hour ago
			Valid: true,
		},
	}, nil)
	mockService.On("CheckUserNoregStatus", mock.Anything, "testuser").Return(false, nil)
	mockService.On("GetUserChannels", mock.Anything, int32(123)).Return([]models.GetUserChannelsRow{}, nil)
	mockService.On("GetUserChannelCount", mock.Anything, int32(123)).Return(int64(0), nil)
	mockService.On("GetUserChannelLimit", mock.Anything, mock.MatchedBy(func(params models.GetUserChannelLimitParams) bool {
		return params.ID == 123
	})).Return(int32(5), nil)
	mockService.On("GetUserPendingRegistrations", mock.Anything, pgtype.Int4{Int32: 123, Valid: true}).Return(int64(0), nil)
}

func setupSupporterValidation(mockService *mocks.ServiceInterface, supporters []string) {
	// Mock the efficient bulk supporter validation
	supporterRows := make([]models.GetSupportersByUsernamesRow, len(supporters))
	for i, supporter := range supporters {
		supporterRows[i] = models.GetSupportersByUsernamesRow{
			ID:           int32(200 + i), // Unique ID
			Username:     supporter,
			SignupTs:     pgtype.Int4{Int32: int32(time.Now().Unix() - 86400*365), Valid: true}, // 1 year old
			Flags:        0,                                                                     // No fraud flags
			Email:        pgtype.Text{String: supporter + "@example.com", Valid: true},
			IsOldEnough:  true,  // Explicitly set to true for testing
			DaysOld:      365,   // 1 year old
			HasFraudFlag: false, // No fraud flag
		}
	}
	mockService.On("GetSupportersByUsernames", mock.Anything, supporters, int32(0)).Return(supporterRows, nil)

	// Mock NOREG status check for supporters
	noregResults := make([]models.CheckMultipleSupportersNoregStatusRow, len(supporters))
	for i, supporter := range supporters {
		noregResults[i] = models.CheckMultipleSupportersNoregStatusRow{
			Username: supporter,
			IsNoreg:  false,
		}
	}
	mockService.On("CheckMultipleSupportersNoregStatus", mock.Anything, supporters).Return(noregResults, nil)

	// Mock concurrent support limits check
	concurrentResults := make([]models.CheckMultipleSupportersConcurrentSupportsRow, len(supporters))
	for i, supporter := range supporters {
		concurrentResults[i] = models.CheckMultipleSupportersConcurrentSupportsRow{
			ID:           int32(200 + i),
			Username:     supporter,
			SupportCount: 0,     // No concurrent supports
			ExceedsLimit: false, // Does not exceed limit
		}
	}
	// Use mock.AnythingOfType to handle different config values in different tests
	mockService.On("CheckMultipleSupportersConcurrentSupports", mock.Anything, supporters, mock.AnythingOfType("int32")).Return(concurrentResults, nil)
}

func setupSuccessfulTransactionMocks(qtx *mocks.ServiceInterface) {
	qtx.On("CreateChannel", mock.Anything, mock.MatchedBy(func(params models.CreateChannelParams) bool {
		return params.Name == "#test"
	})).Return(models.CreateChannelRow{
		ID:   42,
		Name: "#test",
	}, nil)

	qtx.On("CreatePendingChannel", mock.Anything, mock.MatchedBy(func(params models.CreatePendingChannelParams) bool {
		return params.ChannelID == 42
	})).Return(models.CreatePendingChannelRow{
		ChannelID: 42,
		ManagerID: pgtype.Int4{Int32: 123, Valid: true},
		CreatedTs: int32(time.Now().Unix()),
	}, nil)

	qtx.On("GetUser", mock.Anything, models.GetUserParams{Username: "user1"}).Return(models.GetUserRow{
		ID:       201,
		Username: "user1",
	}, nil)
	qtx.On("GetUser", mock.Anything, models.GetUserParams{Username: "user2"}).Return(models.GetUserRow{
		ID:       202,
		Username: "user2",
	}, nil)

	qtx.On("CreateChannelSupporter", mock.Anything, int32(42), int32(201)).Return(nil)
	qtx.On("CreateChannelSupporter", mock.Anything, int32(42), int32(202)).Return(nil)
}
