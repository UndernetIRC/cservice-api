// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package controllers

import (
	"context"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
	"github.com/undernetirc/cservice-api/internal/helper"
)

// DBInterface defines the interface for database operations
type DBInterface interface {
	Ping(ctx context.Context) error
}

// RedisInterface defines the interface for Redis operations
type RedisInterface interface {
	Ping(ctx context.Context) *redis.StatusCmd
}

type HealthCheckController struct {
	dbPool DBInterface
	rdb    RedisInterface
}

func NewHealthCheckController(dbPool *pgxpool.Pool, rdb *redis.Client) *HealthCheckController {
	return &HealthCheckController{dbPool: dbPool, rdb: rdb}
}

type HealthCheckResponse struct {
	Status   string `json:"status"`
	Postgres string `json:"postgres,omitempty"`
	Redis    string `json:"redis,omitempty"`
}

func (ctr *HealthCheckController) HealthCheck(c echo.Context) error {
	logger := helper.GetRequestLogger(c)

	resp := new(HealthCheckResponse)
	resp.Status = "OK"
	resp.Postgres = "UP"
	resp.Redis = "UP"

	err := ctr.dbPool.Ping(c.Request().Context())
	if err != nil {
		resp.Status = "DEGRADED"
		resp.Postgres = "DOWN"
		logger.Warn("Database health check failed",
			"error", err.Error())
	}

	err = ctr.rdb.Ping(c.Request().Context()).Err()
	if err != nil {
		resp.Status = "DEGRADED"
		resp.Redis = "DOWN"
		logger.Warn("Redis health check failed",
			"error", err.Error())
	}

	if resp.Status != "OK" {
		logger.Warn("Health check degraded",
			"status", resp.Status,
			"postgres", resp.Postgres,
			"redis", resp.Redis)
	}

	return c.JSON(http.StatusOK, resp)
}
