// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package controllers

import (
	"net/http"

	"github.com/go-redis/redis/v9"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/labstack/echo/v4"
)

type HealthCheckController struct {
	dbPool *pgxpool.Pool
	rdb    *redis.Client
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
