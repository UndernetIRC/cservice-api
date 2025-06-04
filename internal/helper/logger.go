// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023-2024 UnderNET

package helper

import (
	"log/slog"

	"github.com/labstack/echo/v4"
)

// GetRequestLogger returns a slog.Logger that automatically includes the request ID
// from the Echo context in all log entries. If no request ID is found, it uses "unknown".
func GetRequestLogger(c echo.Context) *slog.Logger {
	requestID := c.Response().Header().Get(echo.HeaderXRequestID)
	if requestID == "" {
		requestID = "unknown"
	}

	return slog.With("requestID", requestID)
}

// GetRequestID extracts the request ID from the Echo context.
// Returns "unknown" if no request ID is found.
func GetRequestID(c echo.Context) string {
	requestID := c.Response().Header().Get(echo.HeaderXRequestID)
	if requestID == "" {
		requestID = "unknown"
	}
	return requestID
}
