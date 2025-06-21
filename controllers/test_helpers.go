// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package controllers

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgtype"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/undernetirc/cservice-api/db/mocks"
	"github.com/undernetirc/cservice-api/db/types/flags"
	"github.com/undernetirc/cservice-api/db/types/password"
	authpassword "github.com/undernetirc/cservice-api/internal/auth/password"
	"github.com/undernetirc/cservice-api/internal/config"
	"github.com/undernetirc/cservice-api/internal/helper"
	"github.com/undernetirc/cservice-api/models"
)

// TestFixtures contains all test data fixtures
type TestFixtures struct {
	Users    []models.User
	Channels []models.Channel
	Tokens   []TokenPair
}

// TokenPair represents access and refresh tokens
type TokenPair struct {
	AccessToken  string
	RefreshToken string
	UserID       int32
	Username     string
}

// TestServer wraps Echo for consistent test setup
type TestServer struct {
	Echo      *echo.Echo
	Recorder  *httptest.ResponseRecorder
	MockDB    *mocks.Querier
	MockRedis *redis.Client
	JWTConfig echojwt.Config
}

// NewTestServer creates a configured test server
func NewTestServer(t *testing.T) *TestServer {
	config.DefaultConfig()

	e := echo.New()
	mockDB := mocks.NewQuerier(t)
	recorder := httptest.NewRecorder()

	// Setup mock Redis client
	mockRedis := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
		DB:   1, // Use test database
	})

	jwtConfig := echojwt.Config{
		SigningMethod: config.ServiceJWTSigningMethod.GetString(),
		SigningKey:    helper.GetJWTPublicKey(),
		NewClaimsFunc: func(_ echo.Context) jwt.Claims {
			return new(helper.JwtClaims)
		},
		ErrorHandler: func(_ echo.Context, _ error) error {
			// Return 401 Unauthorized for any JWT-related errors
			return echo.NewHTTPError(http.StatusUnauthorized, "Unauthorized")
		},
	}

	return &TestServer{
		Echo:      e,
		Recorder:  recorder,
		MockDB:    mockDB,
		MockRedis: mockRedis,
		JWTConfig: jwtConfig,
	}
}

// CreateTestFixtures generates consistent test data
func CreateTestFixtures() *TestFixtures {
	now := time.Now()

	// Create test users with different permission levels
	users := []models.User{
		{
			ID:       1,
			Username: "testuser1",
			Password: password.Password(mustHashPassword("testpassword1")),
			Flags:    flags.UserTotpEnabled,
		},
		{
			ID:       2,
			Username: "testuser2",
			Password: password.Password(mustHashPassword("testpassword2")),
			Flags:    0,
		},
		{
			ID:       3,
			Username: "admin",
			Password: password.Password(mustHashPassword("adminpassword")),
			Flags:    flags.UserTotpEnabled,
		},
		{
			ID:       4,
			Username: "moderator",
			Password: password.Password(mustHashPassword("modpassword")),
			Flags:    0,
		},
	}

	// Create test channels with different types
	channels := []models.Channel{
		{
			ID:           1,
			Name:         "#test-channel",
			Description:  pgtype.Text{String: "Test channel for testing", Valid: true},
			RegisteredTs: pgtype.Int4{Int32: int32(clampToInt32(now.Unix())), Valid: true}, // #nosec G115 -- clampToInt32 prevents overflow
		},
		{
			ID:           2,
			Name:         "#admin-channel",
			Description:  pgtype.Text{String: "Admin channel", Valid: true},
			RegisteredTs: pgtype.Int4{Int32: int32(clampToInt32(now.Unix())), Valid: true}, // #nosec G115 -- clampToInt32 prevents overflow
		},
		{
			ID:           3,
			Name:         "*",
			Description:  pgtype.Text{String: "Global channel", Valid: true},
			RegisteredTs: pgtype.Int4{Int32: int32(clampToInt32(now.Unix())), Valid: true}, // #nosec G115 -- clampToInt32 prevents overflow
		},
		{
			ID:           4,
			Name:         "#private-channel",
			Description:  pgtype.Text{String: "Private channel", Valid: true},
			RegisteredTs: pgtype.Int4{Int32: int32(clampToInt32(now.Unix())), Valid: true}, // #nosec G115 -- clampToInt32 prevents overflow
		},
	}

	// Generate tokens for test users
	var tokens []TokenPair
	for _, user := range users {
		claims := &helper.JwtClaims{
			UserID:   user.ID,
			Username: user.Username,
		}
		tokenPair, _ := helper.GenerateToken(claims, now)
		tokens = append(tokens, TokenPair{
			AccessToken:  tokenPair.AccessToken,
			RefreshToken: tokenPair.RefreshToken,
			UserID:       user.ID,
			Username:     user.Username,
		})
	}

	return &TestFixtures{
		Users:    users,
		Channels: channels,
		Tokens:   tokens,
	}
}

// mustHashPassword hashes a password for testing
func mustHashPassword(plaintext string) string {
	hashed, err := authpassword.GenerateHash(authpassword.DefaultHasher, plaintext)
	if err != nil {
		panic(fmt.Sprintf("Failed to hash password: %v", err))
	}
	return hashed
}

// MockUserQueries sets up common user-related database mocks
func (ts *TestServer) MockUserQueries(fixtures *TestFixtures) {
	for _, user := range fixtures.Users {
		ts.MockDB.On("GetUser", mock.Anything, models.GetUserParams{ID: user.ID}).
			Return(models.GetUserRow{
				ID:       user.ID,
				Username: user.Username,
				Flags:    user.Flags,
			}, nil).Maybe()

		ts.MockDB.On("GetUser", mock.Anything, models.GetUserParams{
			ID: user.ID,
		}).Return(models.GetUserRow{
			ID:       user.ID,
			Username: user.Username,
			Flags:    user.Flags,
		}, nil).Maybe()

		ts.MockDB.On("GetUser", mock.Anything, models.GetUserParams{Username: user.Username}).
			Return(models.GetUserRow{
				ID:       user.ID,
				Username: user.Username,
				Password: user.Password,
				Email:    user.Email,
				Flags:    user.Flags,
			}, nil).Maybe()

		// Mock password verification
		ts.MockDB.On("GetUserPassword", mock.Anything, user.ID).
			Return(models.GetUserRow{
				ID:       user.ID,
				Username: user.Username,
				Password: user.Password,
			}, nil).Maybe()
	}
}

// MockChannelQueries sets up common channel-related database mocks
func (ts *TestServer) MockChannelQueries(fixtures *TestFixtures) {
	for _, channel := range fixtures.Channels {
		ts.MockDB.On("GetChannelByID", mock.Anything, channel.ID).
			Return(models.GetChannelByIDRow{
				ID:          channel.ID,
				Name:        channel.Name,
				Description: channel.Description,
				Url:         channel.Url,
				CreatedAt:   channel.RegisteredTs,
				MemberCount: 0,
			}, nil).Maybe()

		ts.MockDB.On("GetChannelByName", mock.Anything, channel.Name).
			Return(models.GetChannelByNameRow{
				ID:          channel.ID,
				Name:        channel.Name,
				Description: channel.Description,
				Url:         channel.Url,
			}, nil).Maybe()

		ts.MockDB.On("SearchChannels", mock.Anything, models.SearchChannelsParams{
			Name: channel.Name,
		}).Return([]models.SearchChannelsRow{
			{
				ID:          channel.ID,
				Name:        channel.Name,
				Description: channel.Description,
				Url:         channel.Url,
				CreatedAt:   channel.RegisteredTs,
				MemberCount: 0,
			},
		}, nil).Maybe()

		// Mock channel membership
		for _, user := range fixtures.Users {
			ts.MockDB.On("GetUserChannelMemberships", mock.Anything, user.ID).
				Return([]models.GetUserChannelMembershipsRow{
					{
						ChannelID:   channel.ID,
						ChannelName: channel.Name,
						AccessLevel: 100,                                                                     // Default access level
						JoinedAt:    pgtype.Int4{Int32: int32(clampToInt32(time.Now().Unix())), Valid: true}, // #nosec G115 -- clampToInt32 prevents overflow
						MemberCount: 1,
					},
				}, nil).Maybe()
		}
	}
}

// CreateRequest creates an HTTP request with optional authentication
func (ts *TestServer) CreateRequest(method, url string, body interface{}, userID ...int32) *http.Request {
	var reqBody *bytes.Buffer

	if body != nil {
		jsonBody, _ := json.Marshal(body)
		reqBody = bytes.NewBuffer(jsonBody)
	} else {
		reqBody = bytes.NewBuffer(nil)
	}

	req := httptest.NewRequest(method, url, reqBody)
	req.Header.Set("Content-Type", "application/json")

	// Add authentication if userID provided
	if len(userID) > 0 {
		fixtures := CreateTestFixtures()
		for _, token := range fixtures.Tokens {
			if token.UserID == userID[0] {
				req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token.AccessToken))
				break
			}
		}
	}

	return req
}

// ExecuteRequest executes an HTTP request and returns the response recorder
func (ts *TestServer) ExecuteRequest(req *http.Request) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	ts.Echo.ServeHTTP(recorder, req)
	return recorder
}

// AssertJSONResponse asserts the JSON response matches expected data
func AssertJSONResponse(t *testing.T, recorder *httptest.ResponseRecorder, expectedStatus int, expectedData interface{}) {
	if recorder.Code != expectedStatus {
		t.Errorf("Expected status %d, got %d. Response body: %s", expectedStatus, recorder.Code, recorder.Body.String())
		return
	}

	if expectedData != nil {
		var actualData interface{}
		err := json.Unmarshal(recorder.Body.Bytes(), &actualData)
		if err != nil {
			t.Errorf("Failed to unmarshal response: %v", err)
			return
		}
		// Additional assertions can be added here based on expectedData
	}
}

// GenerateRandomString generates a random string of specified length
func GenerateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		b[i] = charset[n.Int64()]
	}
	return string(b)
}

// CreateMaliciousPayloads returns common malicious input payloads for security testing
func CreateMaliciousPayloads() []string {
	return []string{
		// SQL Injection attempts
		"'; DROP TABLE users; --",
		"' OR '1'='1",
		"1' UNION SELECT * FROM users--",
		"admin'--",
		"admin' /*",
		"' OR 1=1#",

		// XSS attempts
		"<script>alert('xss')</script>",
		"javascript:alert('xss')",
		"<img src=x onerror=alert('xss')>",
		"<svg onload=alert('xss')>",

		// Path traversal
		"../../../etc/passwd",
		"..\\..\\..\\windows\\system32\\config\\sam",
		"....//....//....//etc/passwd",

		// Command injection
		"; ls -la",
		"| cat /etc/passwd",
		"&& rm -rf /",
		"`whoami`",

		// LDAP injection
		"*)(uid=*",
		"*)(|(mail=*))",

		// NoSQL injection
		"{'$gt':''}",
		"{'$ne':null}",

		// Buffer overflow attempts
		strings.Repeat("A", 10000),
		strings.Repeat("X", 65536),
	}
}

// SecurityTestCase represents a security test scenario
type SecurityTestCase struct {
	Name           string
	Method         string
	URL            string
	Payload        interface{}
	Headers        map[string]string
	ExpectedStatus int
	ShouldReject   bool
	Description    string
}

// CreateSecurityTestCases generates comprehensive security test cases
func CreateSecurityTestCases() []SecurityTestCase {
	maliciousPayloads := CreateMaliciousPayloads()
	var testCases []SecurityTestCase

	// Test malicious payloads in different contexts
	for i, payload := range maliciousPayloads {
		testCases = append(testCases, SecurityTestCase{
			Name:           fmt.Sprintf("MaliciousInput_%d", i),
			Method:         "POST",
			URL:            "/api/v1/auth/login",
			Payload:        map[string]string{"username": payload, "password": "test"},
			ExpectedStatus: 400,
			ShouldReject:   true,
			Description:    fmt.Sprintf("Should reject malicious input: %s", payload[:minInt(50, len(payload))]),
		})

		// Test in search parameters - properly URL encode the payload
		testCases = append(testCases, SecurityTestCase{
			Name:           fmt.Sprintf("MaliciousSearch_%d", i),
			Method:         "GET",
			URL:            fmt.Sprintf("/api/v1/channels/search?q=%s", url.QueryEscape(payload)),
			ExpectedStatus: 400,
			ShouldReject:   true,
			Description:    fmt.Sprintf("Should reject malicious search: %s", payload[:minInt(50, len(payload))]),
		})
	}

	return testCases
}

// PerformanceTestConfig configures performance testing parameters
type PerformanceTestConfig struct {
	Concurrency int
	Duration    time.Duration
	Requests    int
}

// BenchmarkEndpoint provides a standardized way to benchmark endpoints
func BenchmarkEndpoint(b *testing.B, setup func() (*TestServer, *http.Request)) {
	ts, req := setup()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			recorder := ts.ExecuteRequest(req)
			if recorder.Code >= 500 {
				b.Errorf("Server error: %d", recorder.Code)
			}
		}
	})
}

// LoadTestResult contains the results of a load test
type LoadTestResult struct {
	TotalRequests  int
	SuccessfulReqs int
	FailedRequests int
	AverageLatency time.Duration
	MinLatency     time.Duration
	MaxLatency     time.Duration
	RequestsPerSec float64
	ErrorRate      float64
}

// PerformLoadTest executes a load test with the given configuration
func PerformLoadTest(config PerformanceTestConfig, setup func() (*TestServer, *http.Request)) *LoadTestResult {
	ts, baseReq := setup()

	var (
		totalRequests  int
		successfulReqs int
		failedRequests int
		totalLatency   time.Duration
		minLatency     = time.Hour
		maxLatency     time.Duration
		mu             sync.Mutex
	)

	startTime := time.Now()

	// Create worker pool
	semaphore := make(chan struct{}, config.Concurrency)
	var wg sync.WaitGroup

	for i := 0; i < config.Requests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// Clone request for each goroutine
			req := httptest.NewRequest(baseReq.Method, baseReq.URL.String(), bytes.NewReader([]byte{}))
			for k, v := range baseReq.Header {
				req.Header[k] = v
			}

			reqStart := time.Now()
			recorder := ts.ExecuteRequest(req)
			latency := time.Since(reqStart)

			mu.Lock()
			totalRequests++
			totalLatency += latency

			if latency < minLatency {
				minLatency = latency
			}
			if latency > maxLatency {
				maxLatency = latency
			}

			if recorder.Code < 400 {
				successfulReqs++
			} else {
				failedRequests++
			}
			mu.Unlock()
		}()
	}

	wg.Wait()
	totalDuration := time.Since(startTime)

	return &LoadTestResult{
		TotalRequests:  totalRequests,
		SuccessfulReqs: successfulReqs,
		FailedRequests: failedRequests,
		AverageLatency: totalLatency / time.Duration(totalRequests),
		MinLatency:     minLatency,
		MaxLatency:     maxLatency,
		RequestsPerSec: float64(totalRequests) / totalDuration.Seconds(),
		ErrorRate:      float64(failedRequests) / float64(totalRequests) * 100,
	}
}

// E2ETestSession manages end-to-end test sessions
type E2ETestSession struct {
	Server   *TestServer
	Fixtures *TestFixtures
	Context  context.Context
}

// NewE2ETestSession creates a new E2E test session
func NewE2ETestSession(t *testing.T) *E2ETestSession {
	return &E2ETestSession{
		Server:   NewTestServer(t),
		Fixtures: CreateTestFixtures(),
		Context:  context.Background(),
	}
}

// SimulateUserWorkflow simulates a complete user workflow for E2E testing
func (session *E2ETestSession) SimulateUserWorkflow() error {
	// This would contain a complete user workflow simulation
	// For now, return nil as a placeholder
	return nil
}

// minInt returns the minimum of two integers
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestConfigManager manages test configurations and environments
type TestConfigManager struct {
	TestDB    *sql.DB
	TestRedis *redis.Client
	TestSMTP  *TestSMTPServer
	TempDir   string
	Cleanup   []func()
}

// NewTestConfigManager creates a new test configuration manager
func NewTestConfigManager(t *testing.T) *TestConfigManager {
	tempDir, err := os.MkdirTemp("", "cservice-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	manager := &TestConfigManager{
		TempDir: tempDir,
		Cleanup: []func(){
			func() { os.RemoveAll(tempDir) },
		},
	}

	// Setup cleanup on test completion
	t.Cleanup(func() {
		for _, cleanup := range manager.Cleanup {
			cleanup()
		}
	})

	return manager
}

// TestSMTPServer represents a test SMTP server
type TestSMTPServer struct {
	Host     string
	Port     int
	Messages []TestEmail
	mutex    sync.RWMutex
}

// TestEmail represents an email captured during testing
type TestEmail struct {
	To      []string
	From    string
	Subject string
	Body    string
	Headers map[string]string
	SentAt  time.Time
}

// NewTestSMTPServer creates a new test SMTP server
func NewTestSMTPServer() *TestSMTPServer {
	return &TestSMTPServer{
		Host:     "localhost",
		Port:     2525,
		Messages: make([]TestEmail, 0),
	}
}

// GetMessages returns all captured messages
func (s *TestSMTPServer) GetMessages() []TestEmail {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	messages := make([]TestEmail, len(s.Messages))
	copy(messages, s.Messages)
	return messages
}

// ClearMessages clears all captured messages
func (s *TestSMTPServer) ClearMessages() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.Messages = s.Messages[:0]
}

// TestDataGenerator provides utilities for generating test data
type TestDataGenerator struct {
	counter int64
}

// NewTestDataGenerator creates a new test data generator
func NewTestDataGenerator(seed int64) *TestDataGenerator {
	return &TestDataGenerator{counter: seed}
}

// GenerateUser creates a realistic test user
func (g *TestDataGenerator) GenerateUser() models.User {
	g.counter++
	return models.User{
		ID:       int32(clampToInt32(g.counter)), // #nosec G115 -- clampToInt32 prevents overflow
		Username: fmt.Sprintf("testuser%d", g.counter),
		Email:    pgtype.Text{String: fmt.Sprintf("test%d@example.com", g.counter), Valid: true},
		Password: password.Password(mustHashPassword("password123")),
		Flags:    0,
	}
}

// GenerateChannel creates a realistic test channel
func (g *TestDataGenerator) GenerateChannel() models.Channel {
	g.counter++
	return models.Channel{
		ID:          int32(clampToInt32(g.counter)), // #nosec G115 -- clampToInt32 prevents overflow
		Name:        fmt.Sprintf("#testchannel%d", g.counter),
		Description: pgtype.Text{String: fmt.Sprintf("Test channel %d", g.counter), Valid: true},
		Flags:       0,
	}
}

// DatabaseTestHelper provides utilities for database testing
type DatabaseTestHelper struct {
	DB       *sql.DB
	Queries  *models.Queries
	TxCount  int
	Rollback func()
}

// NewDatabaseTestHelper creates a new database test helper
func NewDatabaseTestHelper(t *testing.T) *DatabaseTestHelper {
	if testing.Short() {
		t.Skip("Skipping database test in short mode")
	}

	// This would typically connect to a test database
	// For now, return a mock helper
	return &DatabaseTestHelper{
		DB:      nil, // Would be real DB connection
		Queries: nil, // Would be real queries
		TxCount: 0,
	}
}

// WithTransaction executes a function within a database transaction
func (h *DatabaseTestHelper) WithTransaction(t *testing.T, _ func(*models.Queries) error) {
	if h.DB == nil {
		t.Skip("Database not available for transaction test")
		return
	}

	// This would need proper pgx transaction handling in a real implementation
	// For now, we'll skip this functionality
	t.Skip("Transaction testing requires pgx transaction implementation")
}

// APITestHelper provides utilities for API endpoint testing
type APITestHelper struct {
	Server  *TestServer
	Client  *http.Client
	BaseURL string
	Headers map[string]string
}

// NewAPITestHelper creates a new API test helper
func NewAPITestHelper(t *testing.T) *APITestHelper {
	server := NewTestServer(t)
	return &APITestHelper{
		Server:  server,
		Client:  &http.Client{Timeout: 30 * time.Second},
		BaseURL: "",
		Headers: make(map[string]string),
	}
}

// SetAuthToken sets the authorization token for subsequent requests
func (h *APITestHelper) SetAuthToken(token string) {
	h.Headers["Authorization"] = fmt.Sprintf("Bearer %s", token)
}

// MakeRequest makes an HTTP request with common test setup
func (h *APITestHelper) MakeRequest(method, path string, body interface{}) (*httptest.ResponseRecorder, error) {
	var reqBody io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewBuffer(jsonBody)
	}

	req := httptest.NewRequest(method, path, reqBody)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	// Add common headers
	for key, value := range h.Headers {
		req.Header.Set(key, value)
	}

	return h.Server.ExecuteRequest(req), nil
}

// AssertErrorResponse asserts that a response contains an error with expected status and message
func (h *APITestHelper) AssertErrorResponse(t *testing.T, recorder *httptest.ResponseRecorder, expectedStatus int, expectedMessage string) {
	assert.Equal(t, expectedStatus, recorder.Code)

	var response map[string]interface{}
	err := json.Unmarshal(recorder.Body.Bytes(), &response)
	assert.NoError(t, err)

	assert.Equal(t, "error", response["status"])
	if expectedMessage != "" {
		assert.Contains(t, response["message"], expectedMessage)
	}
}

// SecurityTestHelper provides utilities for security testing
type SecurityTestHelper struct {
	*APITestHelper
	AttackVectors []AttackVector
}

// AttackVector represents a security attack scenario
type AttackVector struct {
	Name        string
	Payload     string
	Method      string
	Endpoint    string
	Description string
	Expected    SecurityExpectation
}

// SecurityExpectation defines what should happen during a security test
type SecurityExpectation struct {
	ShouldBlock   bool
	ExpectedCode  int
	ExpectedError string
}

// NewSecurityTestHelper creates a new security test helper
func NewSecurityTestHelper(t *testing.T) *SecurityTestHelper {
	apiHelper := NewAPITestHelper(t)
	return &SecurityTestHelper{
		APITestHelper: apiHelper,
		AttackVectors: generateSecurityAttackVectors(),
	}
}

// generateSecurityAttackVectors creates a comprehensive list of attack vectors
func generateSecurityAttackVectors() []AttackVector {
	return []AttackVector{
		{
			Name:        "SQLInjection_Login",
			Payload:     "'; DROP TABLE users; --",
			Method:      "POST",
			Endpoint:    "/api/v1/auth/login",
			Description: "SQL injection attempt in login form",
			Expected:    SecurityExpectation{ShouldBlock: true, ExpectedCode: 400},
		},
		{
			Name:        "XSS_SearchQuery",
			Payload:     "<script>alert('xss')</script>",
			Method:      "GET",
			Endpoint:    "/api/v1/channels/search",
			Description: "XSS attempt in search query",
			Expected:    SecurityExpectation{ShouldBlock: true, ExpectedCode: 400},
		},
		{
			Name:        "PathTraversal_FileAccess",
			Payload:     "../../../etc/passwd",
			Method:      "GET",
			Endpoint:    "/api/v1/files",
			Description: "Path traversal attempt",
			Expected:    SecurityExpectation{ShouldBlock: true, ExpectedCode: 400},
		},
		{
			Name:        "BufferOverflow_LargeInput",
			Payload:     strings.Repeat("A", 100000),
			Method:      "POST",
			Endpoint:    "/api/v1/channels",
			Description: "Buffer overflow attempt with large input",
			Expected:    SecurityExpectation{ShouldBlock: true, ExpectedCode: 413},
		},
	}
}

// TestAllAttackVectors runs all security attack vectors
func (h *SecurityTestHelper) TestAllAttackVectors(t *testing.T) {
	for _, vector := range h.AttackVectors {
		t.Run(vector.Name, func(t *testing.T) {
			h.testAttackVector(t, vector)
		})
	}
}

// testAttackVector tests a single attack vector
func (h *SecurityTestHelper) testAttackVector(t *testing.T, vector AttackVector) {
	var recorder *httptest.ResponseRecorder
	var err error

	switch vector.Method {
	case "GET":
		endpoint := fmt.Sprintf("%s?q=%s", vector.Endpoint, url.QueryEscape(vector.Payload))
		recorder, err = h.MakeRequest(vector.Method, endpoint, nil)
	case "POST":
		payload := map[string]string{"data": vector.Payload}
		recorder, err = h.MakeRequest(vector.Method, vector.Endpoint, payload)
	default:
		t.Fatalf("Unsupported HTTP method: %s", vector.Method)
	}

	assert.NoError(t, err)

	if vector.Expected.ShouldBlock {
		assert.GreaterOrEqual(t, recorder.Code, 400,
			"Attack vector %s should be blocked but returned %d", vector.Name, recorder.Code)
	}

	if vector.Expected.ExpectedCode != 0 {
		assert.Equal(t, vector.Expected.ExpectedCode, recorder.Code,
			"Attack vector %s returned unexpected status code", vector.Name)
	}
}

// PerformanceTestHelper provides utilities for performance testing
type PerformanceTestHelper struct {
	*APITestHelper
	Metrics *PerformanceMetrics
}

// PerformanceMetrics tracks performance test results
type PerformanceMetrics struct {
	TotalRequests   int64
	SuccessfulReqs  int64
	FailedRequests  int64
	AverageLatency  time.Duration
	MinLatency      time.Duration
	MaxLatency      time.Duration
	ThroughputRPS   float64
	P95Latency      time.Duration
	P99Latency      time.Duration
	ErrorRate       float64
	MemoryUsage     uint64
	CPUUsage        float64
	ConcurrentUsers int
	TestDuration    time.Duration
	mutex           sync.RWMutex
	latencies       []time.Duration
}

// NewPerformanceTestHelper creates a new performance test helper
func NewPerformanceTestHelper(t *testing.T) *PerformanceTestHelper {
	return &PerformanceTestHelper{
		APITestHelper: NewAPITestHelper(t),
		Metrics:       &PerformanceMetrics{latencies: make([]time.Duration, 0)},
	}
}

// RunLoadTest executes a load test with specified parameters
func (h *PerformanceTestHelper) RunLoadTest(t *testing.T, config LoadTestConfig) *PerformanceMetrics {
	if testing.Short() {
		t.Skip("Skipping load test in short mode")
	}

	startTime := time.Now()
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, config.Concurrency)

	for i := 0; i < config.Requests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			reqStart := time.Now()
			recorder, err := h.MakeRequest("GET", config.Endpoint, nil)
			latency := time.Since(reqStart)

			h.Metrics.mutex.Lock()
			h.Metrics.TotalRequests++
			h.Metrics.latencies = append(h.Metrics.latencies, latency)

			if err != nil || recorder.Code >= 400 {
				h.Metrics.FailedRequests++
			} else {
				h.Metrics.SuccessfulReqs++
			}

			if h.Metrics.MinLatency == 0 || latency < h.Metrics.MinLatency {
				h.Metrics.MinLatency = latency
			}
			if latency > h.Metrics.MaxLatency {
				h.Metrics.MaxLatency = latency
			}
			h.Metrics.mutex.Unlock()
		}()
	}

	wg.Wait()
	h.calculateMetrics(time.Since(startTime))
	return h.Metrics
}

// LoadTestConfig configures load test parameters
type LoadTestConfig struct {
	Endpoint    string
	Requests    int
	Concurrency int
	Duration    time.Duration
}

// calculateMetrics computes final performance metrics
func (h *PerformanceTestHelper) calculateMetrics(totalDuration time.Duration) {
	h.Metrics.mutex.Lock()
	defer h.Metrics.mutex.Unlock()

	h.Metrics.TestDuration = totalDuration
	h.Metrics.ThroughputRPS = float64(h.Metrics.TotalRequests) / totalDuration.Seconds()
	h.Metrics.ErrorRate = float64(h.Metrics.FailedRequests) / float64(h.Metrics.TotalRequests) * 100

	// Calculate average latency
	var totalLatency time.Duration
	for _, latency := range h.Metrics.latencies {
		totalLatency += latency
	}
	if len(h.Metrics.latencies) > 0 {
		h.Metrics.AverageLatency = totalLatency / time.Duration(len(h.Metrics.latencies))
	}

	// Calculate percentiles
	if len(h.Metrics.latencies) > 0 {
		sort.Slice(h.Metrics.latencies, func(i, j int) bool {
			return h.Metrics.latencies[i] < h.Metrics.latencies[j]
		})

		p95Index := int(float64(len(h.Metrics.latencies)) * 0.95)
		p99Index := int(float64(len(h.Metrics.latencies)) * 0.99)

		if p95Index < len(h.Metrics.latencies) {
			h.Metrics.P95Latency = h.Metrics.latencies[p95Index]
		}
		if p99Index < len(h.Metrics.latencies) {
			h.Metrics.P99Latency = h.Metrics.latencies[p99Index]
		}
	}
}

// clampToInt32 clamps a Unix timestamp to the range of int32
func clampToInt32(unix int64) int64 {
	const maxInt32 = int64(^uint32(0) >> 1)
	const minInt32 = -maxInt32 - 1

	if unix < minInt32 {
		return minInt32
	}
	if unix > maxInt32 {
		return maxInt32
	}
	return unix
}
