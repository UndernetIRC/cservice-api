// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2024 UnderNET

package benchmarks

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/undernetirc/cservice-api/controllers"
	authpassword "github.com/undernetirc/cservice-api/internal/auth/password"
	"github.com/undernetirc/cservice-api/internal/config"
	"github.com/undernetirc/cservice-api/internal/helper"
)

var (
	benchmarkApp   *echo.Echo
	benchmarkToken string
)

func init() {
	// Initialize benchmark environment
	config.DefaultConfig()
	benchmarkApp = setupBenchmarkApp()
	benchmarkToken = setupBenchmarkAuth()
}

// BenchmarkJSONOperations tests JSON marshaling/unmarshaling performance
func BenchmarkJSONOperations(b *testing.B) {
	b.Run("UserResponseMarshal", func(b *testing.B) {
		benchmarkUserResponseMarshal(b)
	})

	b.Run("LoginRequestUnmarshal", func(b *testing.B) {
		benchmarkLoginRequestUnmarshal(b)
	})

	b.Run("ChannelResponseMarshal", func(b *testing.B) {
		benchmarkChannelResponseMarshal(b)
	})
}

// BenchmarkMiddleware tests middleware performance impact
func BenchmarkMiddleware(b *testing.B) {
	b.Run("NoMiddleware", func(b *testing.B) {
		benchmarkNoMiddleware(b)
	})

	b.Run("WithJWTContext", func(b *testing.B) {
		benchmarkWithJWTContext(b)
	})

	b.Run("EchoContextCreation", func(b *testing.B) {
		benchmarkEchoContextCreation(b)
	})
}

// BenchmarkCryptographicOperations tests crypto performance
func BenchmarkCryptographicOperations(b *testing.B) {
	b.Run("PasswordHashing", func(b *testing.B) {
		benchmarkPasswordHashing(b)
	})

	b.Run("JWTGeneration", func(b *testing.B) {
		benchmarkJWTGeneration(b)
	})

	b.Run("JWTValidation", func(b *testing.B) {
		benchmarkJWTValidation(b)
	})
}

// BenchmarkHTTPOperations tests HTTP request/response handling
func BenchmarkHTTPOperations(b *testing.B) {
	b.Run("RequestParsing", func(b *testing.B) {
		benchmarkRequestParsing(b)
	})

	b.Run("ResponseWriting", func(b *testing.B) {
		benchmarkResponseWriting(b)
	})

	b.Run("HeaderProcessing", func(b *testing.B) {
		benchmarkHeaderProcessing(b)
	})
}

// BenchmarkConcurrentOperations tests performance under concurrent load
func BenchmarkConcurrentOperations(b *testing.B) {
	b.Run("ConcurrentJSONMarshal", func(b *testing.B) {
		benchmarkConcurrentJSONMarshal(b)
	})

	b.Run("ConcurrentPasswordHashing", func(b *testing.B) {
		benchmarkConcurrentPasswordHashing(b)
	})

	b.Run("ConcurrentContextHandling", func(b *testing.B) {
		benchmarkConcurrentContextHandling(b)
	})
}

// BenchmarkSpecificOperations tests specific operations that are known bottlenecks
func BenchmarkSpecificOperations(b *testing.B) {
	b.Run("ValidationPerformance", func(b *testing.B) {
		benchmarkValidationPerformance(b)
	})

	b.Run("ErrorHandling", func(b *testing.B) {
		benchmarkErrorHandling(b)
	})

	b.Run("MemoryAllocation", func(b *testing.B) {
		benchmarkMemoryAllocation(b)
	})
}

// Individual benchmark functions

func benchmarkUserResponseMarshal(b *testing.B) {
	data := controllers.UserResponse{
		Username: "benchmark_user",
		Channels: []controllers.ChannelMembership{
			{ChannelName: "#benchmark", AccessLevel: 300, MemberCount: 100},
			{ChannelName: "#dev", AccessLevel: 500, MemberCount: 50},
			{ChannelName: "#test", AccessLevel: 400, MemberCount: 75},
		},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = json.Marshal(data)
	}
}

func benchmarkLoginRequestUnmarshal(b *testing.B) {
	jsonData := []byte(`{"username":"benchmark_user","password":"benchmark_password123"}`)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		var loginReq struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		_ = json.Unmarshal(jsonData, &loginReq)
	}
}

func benchmarkChannelResponseMarshal(b *testing.B) {
	data := controllers.SearchChannelsResponse{
		Channels: []controllers.ChannelSearchResult{
			{ID: 1, Name: "#benchmark", Description: "Benchmark channel", MemberCount: 100},
			{ID: 2, Name: "#dev", Description: "Development channel", MemberCount: 50},
			{ID: 3, Name: "#test", Description: "Testing channel", MemberCount: 75},
		},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = json.Marshal(data)
	}
}

func benchmarkNoMiddleware(b *testing.B) {
	e := echo.New()
	handler := func(c echo.Context) error {
		return c.String(http.StatusOK, "OK")
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		_ = handler(c)
	}
}

func benchmarkWithJWTContext(b *testing.B) {
	e := echo.New()
	handler := func(c echo.Context) error {
		claims := helper.GetClaimsFromContext(c)
		if claims != nil {
			return c.JSON(http.StatusOK, map[string]interface{}{
				"user_id":  claims.UserID,
				"username": claims.Username,
			})
		}
		return c.String(http.StatusUnauthorized, "Unauthorized")
	}

	claims := &helper.JwtClaims{
		UserID:   1,
		Username: "benchmark_user",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("user", claims)

		_ = handler(c)
	}
}

func benchmarkEchoContextCreation(b *testing.B) {
	e := echo.New()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		_ = e.NewContext(req, rec)
	}
}

func benchmarkPasswordHashing(b *testing.B) {
	passwordText := "benchmark_password_123!"

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = authpassword.GenerateHash(authpassword.DefaultHasher, passwordText)
	}
}

func benchmarkJWTGeneration(b *testing.B) {
	claims := &helper.JwtClaims{
		UserID:   1,
		Username: "benchmark_user",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = helper.GenerateToken(claims, time.Now())
	}
}

func benchmarkJWTValidation(b *testing.B) {
	// Pre-generate a token for validation benchmarking
	claims := &helper.JwtClaims{
		UserID:   1,
		Username: "benchmark_user",
	}

	tokens, err := helper.GenerateToken(claims, time.Now())
	if err != nil {
		b.Fatal("Failed to generate token for benchmark:", err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Simulate token validation by getting claims from context
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("user", claims)

		_ = helper.GetClaimsFromContext(c)
	}
}

func benchmarkRequestParsing(b *testing.B) {
	e := echo.New()
	e.Validator = helper.NewValidator()

	jsonBody := `{"username":"benchmark_user","password":"benchmark_password123"}`

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		var loginReq struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		_ = c.Bind(&loginReq)
		_ = c.Validate(&loginReq)
	}
}

func benchmarkResponseWriting(b *testing.B) {
	response := controllers.UserResponse{
		Username: "benchmark_user",
		Channels: []controllers.ChannelMembership{
			{ChannelName: "#benchmark", AccessLevel: 300, MemberCount: 100},
		},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		_ = c.JSON(http.StatusOK, response)
	}
}

func benchmarkHeaderProcessing(b *testing.B) {
	e := echo.New()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+benchmarkToken)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "benchmark-client/1.0")
		req.Header.Set("X-Forwarded-For", "192.168.1.100")

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		// Simulate header processing
		_ = c.Request().Header.Get("Authorization")
		_ = c.Request().Header.Get("Content-Type")
		_ = c.Request().Header.Get("User-Agent")
		_ = c.Request().Header.Get("X-Forwarded-For")
	}
}

func benchmarkConcurrentJSONMarshal(b *testing.B) {
	data := controllers.UserResponse{
		Username: "benchmark_user",
		Channels: []controllers.ChannelMembership{
			{ChannelName: "#benchmark", AccessLevel: 300, MemberCount: 100},
			{ChannelName: "#dev", AccessLevel: 500, MemberCount: 50},
		},
	}

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = json.Marshal(data)
		}
	})
}

func benchmarkConcurrentPasswordHashing(b *testing.B) {
	passwordText := "benchmark_password_123!"

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = authpassword.GenerateHash(authpassword.DefaultHasher, passwordText)
		}
	})
}

func benchmarkConcurrentContextHandling(b *testing.B) {
	e := echo.New()
	claims := &helper.JwtClaims{
		UserID:   1,
		Username: "benchmark_user",
	}

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.Set("user", claims)

			_ = helper.GetClaimsFromContext(c)
		}
	})
}

func benchmarkValidationPerformance(b *testing.B) {
	e := echo.New()
	e.Validator = helper.NewValidator()

	loginReq := struct {
		Username string `json:"username" validate:"required,min=2,max=12"`
		Password string `json:"password" validate:"required,max=72"`
	}{
		Username: "benchmark_user",
		Password: "benchmark_password123!",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		_ = c.Validate(&loginReq)
	}
}

func benchmarkErrorHandling(b *testing.B) {
	e := echo.New()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := echo.NewHTTPError(http.StatusBadRequest, "benchmark error")
		_ = c.JSON(err.Code, map[string]string{"error": err.Message.(string)})
	}
}

func benchmarkMemoryAllocation(b *testing.B) {
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Simulate typical memory allocations in a request
		data := make(map[string]interface{})
		data["user_id"] = 1
		data["username"] = "benchmark_user"
		data["channels"] = []string{"#benchmark", "#dev", "#test"}
		data["timestamp"] = time.Now().Unix()

		_, _ = json.Marshal(data)
	}
}

// Helper functions

func setupBenchmarkApp() *echo.Echo {
	e := echo.New()
	e.Validator = helper.NewValidator()
	return e
}

func setupBenchmarkAuth() string {
	// Generate a test JWT token for benchmarks
	claims := &helper.JwtClaims{
		UserID:   1,
		Username: "benchmark_user",
	}

	tokens, err := helper.GenerateToken(claims, time.Now())
	if err != nil {
		return "mock_token_for_benchmarks"
	}

	return tokens.AccessToken
}
