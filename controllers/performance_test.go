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
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/mock"
	"github.com/undernetirc/cservice-api/db/mocks"
	"github.com/undernetirc/cservice-api/internal/config"
	"github.com/undernetirc/cservice-api/internal/helper"
	"github.com/undernetirc/cservice-api/models"
)

// BenchmarkHealthCheck benchmarks the health check endpoint
func BenchmarkHealthCheck(b *testing.B) {
	BenchmarkEndpoint(b, func() (*TestServer, *http.Request) {
		ts := NewTestServer(&testing.T{})
		healthController := NewHealthCheckController(nil, nil)
		ts.Echo.GET("/health-check", healthController.HealthCheck)

		req := httptest.NewRequest("GET", "/health-check", nil)
		return ts, req
	})
}

// BenchmarkUserLogin benchmarks the user login endpoint
func BenchmarkUserLogin(b *testing.B) {
	BenchmarkEndpoint(b, func() (*TestServer, *http.Request) {
		config.DefaultConfig()
		ts := NewTestServer(&testing.T{})
		fixtures := CreateTestFixtures()

		// Setup mocks
		ts.MockUserQueries(fixtures)

		mockRedis := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
		authController := NewAuthenticationController(ts.MockDB, mockRedis, time.Now)
		ts.Echo.POST("/api/v1/auth/login", authController.Login)

		loginData := map[string]string{
			"username": fixtures.Users[0].Username,
			"password": "testpassword",
		}

		jsonBody, _ := json.Marshal(loginData)
		req := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		return ts, req
	})
}

// BenchmarkGetUser benchmarks the get user endpoint
func BenchmarkGetUser(b *testing.B) {
	BenchmarkEndpoint(b, func() (*TestServer, *http.Request) {
		config.DefaultConfig()
		ts := NewTestServer(&testing.T{})
		fixtures := CreateTestFixtures()

		// Setup mocks
		ts.MockUserQueries(fixtures)

		userController := NewUserController(ts.MockDB)
		ts.Echo.GET("/api/v1/users/:id", userController.GetUser)

		req := httptest.NewRequest("GET", "/api/v1/users/1", nil)
		return ts, req
	})
}

// BenchmarkGetCurrentUser benchmarks the get current user endpoint
func BenchmarkGetCurrentUser(b *testing.B) {
	BenchmarkEndpoint(b, func() (*TestServer, *http.Request) {
		config.DefaultConfig()
		ts := NewTestServer(&testing.T{})
		fixtures := CreateTestFixtures()

		// Setup mocks
		ts.MockUserQueries(fixtures)

		userController := NewUserController(ts.MockDB)
		ts.Echo.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
			return func(c echo.Context) error {
				// Mock JWT middleware by setting user claims
				claims := &helper.JwtClaims{
					UserID:   fixtures.Users[0].ID,
					Username: fixtures.Users[0].Username,
				}
				c.Set("user", &jwt.Token{Claims: claims})
				return next(c)
			}
		})
		ts.Echo.GET("/api/v1/user", userController.GetCurrentUser)

		req := httptest.NewRequest("GET", "/api/v1/user", nil)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", fixtures.Tokens[0].AccessToken))

		return ts, req
	})
}

// BenchmarkSearchChannels benchmarks the search channels endpoint
func BenchmarkSearchChannels(b *testing.B) {
	BenchmarkEndpoint(b, func() (*TestServer, *http.Request) {
		ts := NewTestServer(&testing.T{})
		fixtures := CreateTestFixtures()

		// Setup mocks
		ts.MockChannelQueries(fixtures)

		// Mock search results
		searchResults := []models.SearchChannelsRow{
			{
				ID:          1,
				Name:        "#test-channel",
				Description: fixtures.Channels[0].Description,
				MemberCount: 10,
			},
		}

		ts.MockDB.On("SearchChannels", mock.Anything, mock.AnythingOfType("models.SearchChannelsParams")).
			Return(searchResults, nil).Maybe()
		ts.MockDB.On("SearchChannelsCount", mock.Anything, mock.AnythingOfType("string")).
			Return(int64(1), nil).Maybe()

		// Create controller with proper mocks
		mockService := mocks.NewServiceInterface(b)
		mockPool := createMockPool()
		channelController := NewChannelController(mockService, mockPool)
		ts.Echo.GET("/api/v1/channels/search", channelController.SearchChannels)

		req := httptest.NewRequest("GET", "/api/v1/channels/search?q=test&limit=10&offset=0", nil)
		return ts, req
	})
}

// BenchmarkGetChannelSettings benchmarks the get channel settings endpoint
func BenchmarkGetChannelSettings(b *testing.B) {
	BenchmarkEndpoint(b, func() (*TestServer, *http.Request) {
		ts := NewTestServer(&testing.T{})
		fixtures := CreateTestFixtures()

		// Setup mocks
		ts.MockChannelQueries(fixtures)

		// Create controller with proper mocks
		mockService := mocks.NewServiceInterface(b)
		mockPool := createMockPool()
		channelController := NewChannelController(mockService, mockPool)
		ts.Echo.GET("/api/v1/channels/:id", channelController.GetChannelSettings)

		req := httptest.NewRequest("GET", "/api/v1/channels/1", nil)
		return ts, req
	})
}

// BenchmarkJWTVerification benchmarks JWT token verification
func BenchmarkJWTVerification(b *testing.B) {
	config.DefaultConfig()
	ts := NewTestServer(&testing.T{})
	fixtures := CreateTestFixtures()
	token := fixtures.Tokens[0].AccessToken

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

			// Simulate JWT verification
			middleware := echojwt.WithConfig(ts.JWTConfig)
			c := ts.Echo.NewContext(req, httptest.NewRecorder())
			_ = middleware(func(_ echo.Context) error { return nil })(c)
		}
	})
}

// BenchmarkDatabaseQueries benchmarks common database operations
func BenchmarkDatabaseQueries(b *testing.B) {
	ts := NewTestServer(&testing.T{})
	fixtures := CreateTestFixtures()
	ts.MockUserQueries(fixtures)
	ts.MockChannelQueries(fixtures)

	b.Run("GetUser", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = ts.MockDB.GetUser(context.Background(), models.GetUserParams{ID: 1})
		}
	})

	b.Run("GetChannelByID", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = ts.MockDB.GetChannelByID(context.Background(), 1)
		}
	})

	b.Run("SearchChannels", func(b *testing.B) {
		searchResults := []models.SearchChannelsRow{
			{
				ID:          1,
				Name:        "#test-channel",
				Description: fixtures.Channels[0].Description,
				MemberCount: 10,
			},
		}

		ts.MockDB.On("SearchChannels", mock.Anything, mock.AnythingOfType("models.SearchChannelsParams")).
			Return(searchResults, nil).Maybe()

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = ts.MockDB.SearchChannels(context.Background(), models.SearchChannelsParams{
				Name:   "%test%",
				Limit:  10,
				Offset: 0,
			})
		}
	})
}

// BenchmarkJSONSerialization benchmarks JSON serialization/deserialization
func BenchmarkJSONSerialization(b *testing.B) {
	fixtures := CreateTestFixtures()

	b.Run("UserResponse", func(b *testing.B) {
		userResponse := UserResponse{
			ID:       fixtures.Users[0].ID,
			Username: fixtures.Users[0].Username,
			Channels: []ChannelMembership{
				{
					ChannelID:   1,
					ChannelName: "#test",
					AccessLevel: 500,
					JoinedAt:    int32(time.Now().Unix()),
					MemberCount: 10,
				},
			},
			TotpEnabled: true,
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = json.Marshal(userResponse)
		}
	})

	b.Run("LoginRequest", func(b *testing.B) {
		loginData := map[string]string{
			"username": "testuser",
			"password": "testpassword",
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = json.Marshal(loginData)
		}
	})

	b.Run("ChannelSearchResponse", func(b *testing.B) {
		searchResponse := SearchChannelsResponse{
			Channels: []ChannelSearchResult{
				{
					ID:          1,
					Name:        "#test-channel",
					Description: "Test channel",
					MemberCount: 10,
				},
			},
			Pagination: PaginationInfo{
				Total:   1,
				Limit:   10,
				Offset:  0,
				HasMore: false,
			},
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = json.Marshal(searchResponse)
		}
	})
}

// LoadTestHealthCheck performs a load test on the health check endpoint
func LoadTestHealthCheck(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping load test in short mode")
	}

	testConfig := PerformanceTestConfig{
		Concurrency: 10,
		Duration:    5 * time.Second,
		Requests:    100,
	}

	result := PerformLoadTest(testConfig, func() (*TestServer, *http.Request) {
		ts := NewTestServer(&testing.T{})
		healthController := NewHealthCheckController(nil, nil)
		ts.Echo.GET("/health-check", healthController.HealthCheck)

		req := httptest.NewRequest("GET", "/health-check", nil)
		return ts, req
	})

	b.Logf("Load test results:")
	b.Logf("Total requests: %d", result.TotalRequests)
	b.Logf("Successful requests: %d", result.SuccessfulReqs)
	b.Logf("Failed requests: %d", result.FailedRequests)
	b.Logf("Average latency: %v", result.AverageLatency)
	b.Logf("Min latency: %v", result.MinLatency)
	b.Logf("Max latency: %v", result.MaxLatency)
	b.Logf("Requests per second: %.2f", result.RequestsPerSec)
	b.Logf("Error rate: %.2f%%", result.ErrorRate)
}

// LoadTestUserLogin performs a load test on the user login endpoint
func LoadTestUserLogin(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping load test in short mode")
	}

	testConfig := PerformanceTestConfig{
		Concurrency: 5,
		Duration:    3 * time.Second,
		Requests:    50,
	}

	result := PerformLoadTest(testConfig, func() (*TestServer, *http.Request) {
		config.DefaultConfig()
		ts := NewTestServer(&testing.T{})
		fixtures := CreateTestFixtures()

		// Setup mocks
		ts.MockUserQueries(fixtures)

		mockRedis := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
		authController := NewAuthenticationController(ts.MockDB, mockRedis, time.Now)
		ts.Echo.POST("/api/v1/auth/login", authController.Login)

		loginData := map[string]string{
			"username": fixtures.Users[0].Username,
			"password": "testpassword",
		}

		jsonBody, _ := json.Marshal(loginData)
		req := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		return ts, req
	})

	b.Logf("Login load test results:")
	b.Logf("Total requests: %d", result.TotalRequests)
	b.Logf("Successful requests: %d", result.SuccessfulReqs)
	b.Logf("Failed requests: %d", result.FailedRequests)
	b.Logf("Average latency: %v", result.AverageLatency)
	b.Logf("Requests per second: %.2f", result.RequestsPerSec)
	b.Logf("Error rate: %.2f%%", result.ErrorRate)
}
