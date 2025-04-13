//go:build integration

// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package integration

import (
	"encoding/json"

	"github.com/stretchr/testify/assert"
	"github.com/undernetirc/cservice-api/controllers"

	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
)

func TestHealthCheck(t *testing.T) {
	healthCheckController := controllers.NewHealthCheckController(dbPool, rdb)
	e := echo.New()
	e.GET("/health-check", healthCheckController.HealthCheck)

	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "/health-check", nil)

	e.ServeHTTP(w, r)

	resp := w.Result()
	assert.Equal(t, resp.StatusCode, http.StatusOK)

	hcResponse := new(controllers.HealthCheckResponse)
	dec := json.NewDecoder(resp.Body)
	err := dec.Decode(hcResponse)
	if err != nil {
		t.Error("error decoding", err)
	}
	assert.Equal(t, hcResponse.Status, "OK")
}

func BenchmarkHealthCheck(b *testing.B) {
	healthCheckController := controllers.NewHealthCheckController(dbPool, rdb)
	e := echo.New()
	e.GET("/health-check", healthCheckController.HealthCheck)

	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "/health-check", nil)

	for i := 0; i < b.N; i++ {
		e.ServeHTTP(w, r)
	}
}
