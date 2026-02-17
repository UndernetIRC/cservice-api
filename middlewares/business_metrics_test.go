// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

package middlewares

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/metric/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"

	"github.com/undernetirc/cservice-api/internal/metrics"
)

func createTestBusinessMetrics(t *testing.T) *metrics.BusinessMetrics {
	t.Helper()
	meter := noop.NewMeterProvider().Meter("test")
	bm, err := metrics.NewBusinessMetrics(metrics.BusinessMetricsConfig{
		Meter:       meter,
		ServiceName: "test-service",
	})
	require.NoError(t, err)
	return bm
}

func TestBusinessMetricsMiddleware(t *testing.T) {
	t.Run("nil business metrics returns no-op middleware", func(t *testing.T) {
		middleware := BusinessMetricsMiddleware(BusinessMetricsConfig{
			BusinessMetrics: nil,
		})
		assert.NotNil(t, middleware)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		handler := middleware(func(c echo.Context) error {
			return c.String(http.StatusOK, "ok")
		})

		err := handler(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("valid business metrics wraps handler", func(t *testing.T) {
		bm := createTestBusinessMetrics(t)
		middleware := BusinessMetricsMiddleware(BusinessMetricsConfig{
			BusinessMetrics: bm,
		})
		assert.NotNil(t, middleware)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		handlerCalled := false
		handler := middleware(func(c echo.Context) error {
			handlerCalled = true
			return c.String(http.StatusOK, "ok")
		})

		err := handler(c)
		assert.NoError(t, err)
		assert.True(t, handlerCalled)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("skipper skips metrics recording", func(t *testing.T) {
		bm := createTestBusinessMetrics(t)
		middleware := BusinessMetricsMiddleware(BusinessMetricsConfig{
			BusinessMetrics: bm,
			Skipper: func(_ echo.Context) bool {
				return true
			},
		})

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		handler := middleware(func(c echo.Context) error {
			return c.String(http.StatusOK, "ok")
		})

		err := handler(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("handler error is propagated", func(t *testing.T) {
		bm := createTestBusinessMetrics(t)
		middleware := BusinessMetricsMiddleware(BusinessMetricsConfig{
			BusinessMetrics: bm,
		})

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		expectedErr := echo.NewHTTPError(http.StatusInternalServerError, "handler error")
		handler := middleware(func(_ echo.Context) error {
			return expectedErr
		})

		err := handler(c)
		assert.Equal(t, expectedErr, err)
	})
}

func TestBusinessMetricsMiddleware_RecordsOnCompletion(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(resource.Empty()),
		sdkmetric.WithReader(reader),
	)
	meter := provider.Meter("test")

	bm, err := metrics.NewBusinessMetrics(metrics.BusinessMetricsConfig{
		Meter:       meter,
		ServiceName: "test-service",
	})
	require.NoError(t, err)

	middleware := BusinessMetricsMiddleware(BusinessMetricsConfig{
		BusinessMetrics: bm,
	})

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/register", strings.NewReader(`{"username":"newuser","email":"newuser@example.com"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	handler := middleware(func(c echo.Context) error {
		return c.String(http.StatusOK, "registered")
	})

	err = handler(c)
	assert.NoError(t, err)

	ctx := context.Background()
	rm := &metricdata.ResourceMetrics{}
	err = reader.Collect(ctx, rm)
	require.NoError(t, err)
	assert.NotEmpty(t, rm.ScopeMetrics, "Expected metrics to be recorded after request completion")
}

func TestRecordBusinessMetrics(t *testing.T) {
	bm := createTestBusinessMetrics(t)
	ctx := context.Background()
	duration := 100 * time.Millisecond

	t.Run("registration endpoint POST", func(_ *testing.T) {
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/register", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		body := []byte(`{"username":"testuser","email":"test@example.com"}`)

		recordBusinessMetrics(ctx, bm, c, body, http.StatusOK, duration)
	})

	t.Run("activation endpoint POST", func(_ *testing.T) {
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/activate", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		body := []byte(`{"username":"testuser"}`)

		recordBusinessMetrics(ctx, bm, c, body, http.StatusOK, duration)
	})

	t.Run("login endpoint POST", func(_ *testing.T) {
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/login", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("user_id", int32(42))

		recordBusinessMetrics(ctx, bm, c, nil, http.StatusOK, duration)
	})

	t.Run("logout endpoint POST", func(_ *testing.T) {
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/logout", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("user_id", int32(42))

		recordBusinessMetrics(ctx, bm, c, nil, http.StatusOK, duration)
	})

	t.Run("channel search GET", func(_ *testing.T) {
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/channels/search?q=test", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("user_id", int32(10))

		recordBusinessMetrics(ctx, bm, c, nil, http.StatusOK, duration)
	})

	t.Run("channel settings GET", func(_ *testing.T) {
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/channels/5/settings", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("user_id", int32(10))
		c.SetParamNames("id")
		c.SetParamValues("5")

		recordBusinessMetrics(ctx, bm, c, nil, http.StatusOK, duration)
	})

	t.Run("channel settings PUT", func(_ *testing.T) {
		e := echo.New()
		req := httptest.NewRequest(http.MethodPut, "/api/v1/channels/5/settings", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("user_id", int32(10))
		c.SetParamNames("id")
		c.SetParamValues("5")
		body := []byte(`{"description":"new description","url":"https://example.com"}`)

		recordBusinessMetrics(ctx, bm, c, body, http.StatusOK, duration)
	})

	t.Run("channel members POST", func(_ *testing.T) {
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/channels/5/members", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("user_id", int32(10))
		c.SetParamNames("id")
		c.SetParamValues("5")
		body := []byte(`{"user_id":20,"access_level":200}`)

		recordBusinessMetrics(ctx, bm, c, body, http.StatusOK, duration)
	})

	t.Run("channel members DELETE", func(_ *testing.T) {
		e := echo.New()
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/channels/5/members/20", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("user_id", int32(10))
		c.SetParamNames("id", "user_id")
		c.SetParamValues("5", "20")

		recordBusinessMetrics(ctx, bm, c, nil, http.StatusOK, duration)
	})
}

func TestRecordBusinessMetrics_VariousEndpoints(t *testing.T) {
	bm := createTestBusinessMetrics(t)
	ctx := context.Background()
	duration := 50 * time.Millisecond

	tests := []struct {
		name   string
		path   string
		method string
		status int
		body   string
	}{
		{
			name:   "general GET endpoint",
			path:   "/api/v1/users/me",
			method: http.MethodGet,
			status: http.StatusOK,
		},
		{
			name:   "failed registration",
			path:   "/api/v1/register",
			method: http.MethodPost,
			status: http.StatusConflict,
			body:   `{"username":"existing","email":"existing@example.com"}`,
		},
		{
			name:   "failed activation - invalid token",
			path:   "/api/v1/activate",
			method: http.MethodPost,
			status: http.StatusBadRequest,
			body:   `{"username":"testuser"}`,
		},
		{
			name:   "failed activation - expired token",
			path:   "/api/v1/activate",
			method: http.MethodPost,
			status: http.StatusGone,
			body:   `{"username":"testuser"}`,
		},
		{
			name:   "failed activation - not found",
			path:   "/api/v1/activate",
			method: http.MethodPost,
			status: http.StatusNotFound,
			body:   `{"username":"testuser"}`,
		},
		{
			name:   "channel search with query param",
			path:   "/api/v1/channels/search?query=mychannel",
			method: http.MethodGet,
			status: http.StatusOK,
		},
		{
			name:   "server error on channel settings",
			path:   "/api/v1/channels/5/settings",
			method: http.MethodPut,
			status: http.StatusInternalServerError,
			body:   `{"description":"test"}`,
		},
		{
			name:   "failed member add",
			path:   "/api/v1/channels/5/members",
			method: http.MethodPost,
			status: http.StatusForbidden,
			body:   `{"user_id":20}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			e := echo.New()
			req := httptest.NewRequest(tt.method, tt.path, nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			recordBusinessMetrics(ctx, bm, c, []byte(tt.body), tt.status, duration)
			// Test passes if no panic occurs
		})
	}
}

func TestRecordBusinessMetrics_ErrorHandling(t *testing.T) {
	bm := createTestBusinessMetrics(t)
	ctx := context.Background()
	duration := 10 * time.Millisecond

	t.Run("nil request body does not panic", func(t *testing.T) {
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/register", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		assert.NotPanics(t, func() {
			recordBusinessMetrics(ctx, bm, c, nil, http.StatusOK, duration)
		})
	})

	t.Run("invalid JSON body does not panic", func(t *testing.T) {
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/register", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		assert.NotPanics(t, func() {
			recordBusinessMetrics(ctx, bm, c, []byte("invalid json{{{"), http.StatusOK, duration)
		})
	})

	t.Run("empty body on activation does not panic", func(t *testing.T) {
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/activate", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		assert.NotPanics(t, func() {
			recordBusinessMetrics(ctx, bm, c, []byte{}, http.StatusOK, duration)
		})
	})

	t.Run("channel settings update with empty body", func(t *testing.T) {
		e := echo.New()
		req := httptest.NewRequest(http.MethodPut, "/api/v1/channels/5/settings", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		assert.NotPanics(t, func() {
			recordBusinessMetrics(ctx, bm, c, []byte{}, http.StatusOK, duration)
		})
	})

	t.Run("channel member add with malformed body", func(t *testing.T) {
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/channels/5/members", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		assert.NotPanics(t, func() {
			recordBusinessMetrics(ctx, bm, c, []byte("not json"), http.StatusOK, duration)
		})
	})

	t.Run("500 error does not break metrics", func(t *testing.T) {
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/register", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		assert.NotPanics(t, func() {
			recordBusinessMetrics(ctx, bm, c, []byte(`{"username":"u"}`), http.StatusInternalServerError, duration)
		})
	})
}

func TestBusinessMetrics_ExtractorFunctions(t *testing.T) {
	t.Run("extractUserID", func(t *testing.T) {
		tests := []struct {
			name     string
			setup    func(echo.Context)
			expected int32
		}{
			{
				name:     "no user_id in context",
				setup:    func(_ echo.Context) {},
				expected: 0,
			},
			{
				name: "int32 user_id",
				setup: func(c echo.Context) {
					c.Set("user_id", int32(42))
				},
				expected: 42,
			},
			{
				name: "int user_id",
				setup: func(c echo.Context) {
					c.Set("user_id", 99)
				},
				expected: 99,
			},
			{
				name: "string user_id",
				setup: func(c echo.Context) {
					c.Set("user_id", "123")
				},
				expected: 123,
			},
			{
				name: "invalid string user_id",
				setup: func(c echo.Context) {
					c.Set("user_id", "not-a-number")
				},
				expected: 0,
			},
			{
				name: "unsupported type",
				setup: func(c echo.Context) {
					c.Set("user_id", float64(5.5))
				},
				expected: 0,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				e := echo.New()
				req := httptest.NewRequest(http.MethodGet, "/test", nil)
				rec := httptest.NewRecorder()
				c := e.NewContext(req, rec)
				tt.setup(c)

				result := extractUserID(c)
				assert.Equal(t, tt.expected, result)
			})
		}
	})

	t.Run("extractChannelID", func(t *testing.T) {
		tests := []struct {
			name       string
			paramName  string
			paramValue string
			expected   int32
		}{
			{
				name:       "valid id param",
				paramName:  "id",
				paramValue: "42",
				expected:   42,
			},
			{
				name:       "valid channel_id param",
				paramName:  "channel_id",
				paramValue: "99",
				expected:   99,
			},
			{
				name:     "no param",
				expected: 0,
			},
			{
				name:       "invalid param",
				paramName:  "id",
				paramValue: "abc",
				expected:   0,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				e := echo.New()
				req := httptest.NewRequest(http.MethodGet, "/test", nil)
				rec := httptest.NewRecorder()
				c := e.NewContext(req, rec)
				if tt.paramName != "" {
					c.SetParamNames(tt.paramName)
					c.SetParamValues(tt.paramValue)
				}

				result := extractChannelID(c)
				assert.Equal(t, tt.expected, result)
			})
		}
	})

	t.Run("extractAccessLevel", func(t *testing.T) {
		tests := []struct {
			name     string
			setup    func(echo.Context)
			expected int
		}{
			{
				name:     "default access level",
				setup:    func(_ echo.Context) {},
				expected: 100,
			},
			{
				name: "custom access level",
				setup: func(c echo.Context) {
					c.Set("access_level", 500)
				},
				expected: 500,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				e := echo.New()
				req := httptest.NewRequest(http.MethodGet, "/test", nil)
				rec := httptest.NewRecorder()
				c := e.NewContext(req, rec)
				tt.setup(c)

				result := extractAccessLevel(c)
				assert.Equal(t, tt.expected, result)
			})
		}
	})

	t.Run("extractRegistrationInfo", func(t *testing.T) {
		tests := []struct {
			name        string
			body        string
			expectUser  string
			expectEmail string
		}{
			{
				name:        "valid registration body",
				body:        `{"username":"newuser","email":"new@example.com"}`,
				expectUser:  "newuser",
				expectEmail: "new@example.com",
			},
			{
				name:        "empty body",
				body:        "",
				expectUser:  "",
				expectEmail: "",
			},
			{
				name:        "invalid JSON",
				body:        "not json",
				expectUser:  "",
				expectEmail: "",
			},
			{
				name:        "missing fields",
				body:        `{"other":"value"}`,
				expectUser:  "",
				expectEmail: "",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				username, email := extractRegistrationInfo([]byte(tt.body))
				assert.Equal(t, tt.expectUser, username)
				assert.Equal(t, tt.expectEmail, email)
			})
		}
	})

	t.Run("extractUsernameFromActivation", func(t *testing.T) {
		tests := []struct {
			name     string
			body     string
			expected string
		}{
			{
				name:     "valid body",
				body:     `{"username":"activateuser"}`,
				expected: "activateuser",
			},
			{
				name:     "empty body",
				body:     "",
				expected: "",
			},
			{
				name:     "invalid JSON",
				body:     "not json",
				expected: "",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				result := extractUsernameFromActivation([]byte(tt.body))
				assert.Equal(t, tt.expected, result)
			})
		}
	})

	t.Run("extractResultCount", func(t *testing.T) {
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()

		c := e.NewContext(req, rec)
		assert.Equal(t, 0, extractResultCount(c))

		c.Set("result_count", 25)
		assert.Equal(t, 25, extractResultCount(c))
	})

	t.Run("extractUpdatedFields", func(t *testing.T) {
		tests := []struct {
			name    string
			body    string
			hasKeys bool
		}{
			{
				name:    "valid body with fields",
				body:    `{"description":"test","url":"https://example.com"}`,
				hasKeys: true,
			},
			{
				name:    "empty JSON",
				body:    `{}`,
				hasKeys: false,
			},
			{
				name:    "invalid JSON",
				body:    "not json",
				hasKeys: false,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				fields := extractUpdatedFields([]byte(tt.body))
				if tt.hasKeys {
					assert.NotEmpty(t, fields)
				} else {
					assert.Empty(t, fields)
				}
			})
		}
	})

	t.Run("extractTargetUserID", func(t *testing.T) {
		tests := []struct {
			name     string
			body     string
			expected int32
		}{
			{
				name:     "numeric user_id",
				body:     `{"user_id":42}`,
				expected: 42,
			},
			{
				name:     "string user_id",
				body:     `{"user_id":"99"}`,
				expected: 99,
			},
			{
				name:     "missing user_id",
				body:     `{"other":"value"}`,
				expected: 0,
			},
			{
				name:     "invalid JSON",
				body:     "not json",
				expected: 0,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				result := extractTargetUserID([]byte(tt.body))
				assert.Equal(t, tt.expected, result)
			})
		}
	})

	t.Run("extractTargetUserIDFromPath", func(t *testing.T) {
		e := echo.New()
		req := httptest.NewRequest(http.MethodDelete, "/channels/5/members/20", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id", "user_id")
		c.SetParamValues("5", "20")

		assert.Equal(t, int32(20), extractTargetUserIDFromPath(c))

		// No param
		c2 := e.NewContext(httptest.NewRequest(http.MethodDelete, "/test", nil), httptest.NewRecorder())
		assert.Equal(t, int32(0), extractTargetUserIDFromPath(c2))
	})

	t.Run("extractMemberAccessLevel", func(t *testing.T) {
		tests := []struct {
			name     string
			body     string
			expected int
		}{
			{
				name:     "valid access_level",
				body:     `{"access_level":200}`,
				expected: 200,
			},
			{
				name:     "missing access_level",
				body:     `{"user_id":42}`,
				expected: 100,
			},
			{
				name:     "invalid JSON",
				body:     "not json",
				expected: 100,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				result := extractMemberAccessLevel([]byte(tt.body))
				assert.Equal(t, tt.expected, result)
			})
		}
	})

	t.Run("getRegistrationReason", func(t *testing.T) {
		assert.Equal(t, "success", getRegistrationReason(200, true))
		assert.Equal(t, "invalid_data", getRegistrationReason(400, false))
		assert.Equal(t, "username_or_email_exists", getRegistrationReason(409, false))
		assert.Equal(t, "validation_failed", getRegistrationReason(422, false))
		assert.Equal(t, "server_error", getRegistrationReason(500, false))
	})

	t.Run("getActivationReason", func(t *testing.T) {
		assert.Equal(t, "success", getActivationReason(200, true))
		assert.Equal(t, "invalid_token", getActivationReason(400, false))
		assert.Equal(t, "token_not_found", getActivationReason(404, false))
		assert.Equal(t, "token_expired", getActivationReason(410, false))
		assert.Equal(t, "server_error", getActivationReason(500, false))
	})

	t.Run("getOperationType", func(t *testing.T) {
		tests := []struct {
			path     string
			method   string
			expected string
		}{
			{"/api/v1/register", "POST", "user_registration"},
			{"/api/v1/activate", "POST", "user_activation"},
			{"/api/v1/login", "POST", "user_login"},
			{"/api/v1/logout", "POST", "user_logout"},
			{"/api/v1/channels/search", "GET", "channel_search"},
			{"/api/v1/channels/5/settings", "GET", "channel_settings_view"},
			{"/api/v1/channels/5/settings", "PUT", "channel_settings_update"},
			{"/api/v1/channels/5/members", "POST", "channel_member_add"},
			{"/api/v1/channels/5/members/20", "DELETE", "channel_member_remove"},
			{"/api/v1/users/me", "GET", "general_api"},
		}

		for _, tt := range tests {
			t.Run(tt.path+"_"+tt.method, func(t *testing.T) {
				result := getOperationType(tt.path, tt.method)
				assert.Equal(t, tt.expected, result)
			})
		}
	})

	t.Run("getFeatureName", func(t *testing.T) {
		tests := []struct {
			path     string
			method   string
			expected string
		}{
			{"/api/v1/register", "POST", "user_registration"},
			{"/api/v1/activate", "POST", "user_activation"},
			{"/api/v1/channels/search", "GET", "channel_search"},
			{"/api/v1/channels/5/settings", "PUT", "channel_settings"},
			{"/api/v1/channels/5/members", "POST", "channel_members"},
			{"/api/v1/users/me", "GET", ""},
		}

		for _, tt := range tests {
			t.Run(tt.path, func(t *testing.T) {
				result := getFeatureName(tt.path, tt.method)
				assert.Equal(t, tt.expected, result)
			})
		}
	})

	t.Run("calculateErrorRate", func(t *testing.T) {
		assert.Equal(t, 0.0, calculateErrorRate(200))
		assert.Equal(t, 0.0, calculateErrorRate(301))
		assert.Equal(t, 100.0, calculateErrorRate(400))
		assert.Equal(t, 100.0, calculateErrorRate(404))
		assert.Equal(t, 100.0, calculateErrorRate(500))
	})
}
