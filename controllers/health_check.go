// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package controllers

import (
	"context"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
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
	resp := new(HealthCheckResponse)
	resp.Status = "OK"
	resp.Postgres = "UP"
	resp.Redis = "UP"

	err := ctr.dbPool.Ping(c.Request().Context())
	if err != nil {
		resp.Status = "DEGRADED"
		resp.Postgres = "DOWN"
	}
	err = ctr.rdb.Ping(c.Request().Context()).Err()
	if err != nil {
		resp.Status = "DEGRADED"
		resp.Redis = "DOWN"
	}

	return c.JSON(http.StatusOK, resp)
}
