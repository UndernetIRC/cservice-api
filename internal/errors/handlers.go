// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2024 UnderNET

package errors

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
)

// getRequestID extracts request ID from context for logging
func getRequestID(c echo.Context) string {
	requestID := c.Response().Header().Get(echo.HeaderXRequestID)
	if requestID == "" {
		requestID = "unknown"
	}
	return requestID
}

// HandleValidationError handles validation errors with detailed field-level information
func HandleValidationError(c echo.Context, err error) error {
	requestID := getRequestID(c)

	if validationErrors, ok := err.(validator.ValidationErrors); ok {
		details := make(map[string]string)
		for _, e := range validationErrors {
			details[e.Field()] = getValidationErrorMessage(e)
		}

		// Structured logging with slog
		slog.Warn("Validation error",
			"requestID", requestID,
			"path", c.Request().URL.Path,
			"method", c.Request().Method,
			"errors", details)

		return c.JSON(http.StatusBadRequest, NewErrorResponse(
			ErrCodeValidation,
			"Invalid input provided",
			details,
		))
	}

	// Generic validation error
	slog.Warn("Generic validation error",
		"requestID", requestID,
		"path", c.Request().URL.Path,
		"method", c.Request().Method,
		"error", err.Error())

	return c.JSON(http.StatusBadRequest, NewErrorResponse(
		ErrCodeValidation,
		err.Error(),
		nil,
	))
}

// HandleDatabaseError handles database errors by logging details but returning generic message
func HandleDatabaseError(c echo.Context, err error) error {
	requestID := getRequestID(c)

	// Structured logging with slog for database errors
	slog.Error("Database error",
		"requestID", requestID,
		"path", c.Request().URL.Path,
		"method", c.Request().Method,
		"error", err.Error())

	// Return a generic error to the client
	return c.JSON(http.StatusInternalServerError, NewErrorResponse(
		ErrCodeDatabase,
		"An error occurred while processing your request",
		nil,
	))
}

// HandleUnauthorizedError handles authentication failures
func HandleUnauthorizedError(c echo.Context, message string) error {
	if message == "" {
		message = "Authorization information is missing or invalid"
	}

	requestID := getRequestID(c)
	slog.Warn("Unauthorized access attempt",
		"requestID", requestID,
		"path", c.Request().URL.Path,
		"method", c.Request().Method,
		"message", message)

	return c.JSON(http.StatusUnauthorized, NewErrorResponse(
		ErrCodeUnauthorized,
		message,
		nil,
	))
}

// HandleForbiddenError handles authorization failures (user is authenticated but lacks permission)
func HandleForbiddenError(c echo.Context, message string) error {
	if message == "" {
		message = "You do not have permission to access this resource"
	}

	requestID := getRequestID(c)
	slog.Warn("Forbidden access attempt",
		"requestID", requestID,
		"path", c.Request().URL.Path,
		"method", c.Request().Method,
		"message", message)

	return c.JSON(http.StatusForbidden, NewErrorResponse(
		ErrCodeForbidden,
		message,
		nil,
	))
}

// HandleNotFoundError handles resource not found errors
func HandleNotFoundError(c echo.Context, resource string) error {
	message := "Resource not found"
	if resource != "" {
		message = fmt.Sprintf("%s not found", resource)
	}

	requestID := getRequestID(c)
	slog.Info("Resource not found",
		"requestID", requestID,
		"path", c.Request().URL.Path,
		"method", c.Request().Method,
		"resource", resource)

	return c.JSON(http.StatusNotFound, NewErrorResponse(
		ErrCodeNotFound,
		message,
		nil,
	))
}

// HandleConflictError handles resource conflict errors
func HandleConflictError(c echo.Context, message string) error {
	if message == "" {
		message = "Resource conflict"
	}

	requestID := getRequestID(c)
	slog.Warn("Resource conflict",
		"requestID", requestID,
		"path", c.Request().URL.Path,
		"method", c.Request().Method,
		"message", message)

	return c.JSON(http.StatusConflict, NewErrorResponse(
		ErrCodeConflict,
		message,
		nil,
	))
}

// HandleBadRequestError handles malformed request errors
func HandleBadRequestError(c echo.Context, message string) error {
	if message == "" {
		message = "Bad request"
	}

	requestID := getRequestID(c)
	slog.Warn("Bad request",
		"requestID", requestID,
		"path", c.Request().URL.Path,
		"method", c.Request().Method,
		"message", message)

	return c.JSON(http.StatusBadRequest, NewErrorResponse(
		ErrCodeBadRequest,
		message,
		nil,
	))
}

// HandleUnprocessableEntityError handles business logic validation errors
func HandleUnprocessableEntityError(c echo.Context, message string) error {
	if message == "" {
		message = "Request cannot be processed"
	}

	requestID := getRequestID(c)
	slog.Warn("Unprocessable entity",
		"requestID", requestID,
		"path", c.Request().URL.Path,
		"method", c.Request().Method,
		"message", message)

	return c.JSON(http.StatusUnprocessableEntity, NewErrorResponse(
		ErrCodeUnprocessable,
		message,
		nil,
	))
}

// HandleInternalError handles unexpected internal server errors
func HandleInternalError(c echo.Context, err error, message string) error {
	if message == "" {
		message = "Internal server error"
	}

	requestID := getRequestID(c)
	slog.Error("Internal server error",
		"requestID", requestID,
		"path", c.Request().URL.Path,
		"method", c.Request().Method,
		"error", err.Error(),
		"publicMessage", message)

	return c.JSON(http.StatusInternalServerError, NewErrorResponse(
		ErrCodeInternal,
		message,
		nil,
	))
}

// getValidationErrorMessage converts validator field errors to human-readable messages
func getValidationErrorMessage(fe validator.FieldError) string {
	switch fe.Tag() {
	case "required":
		return "This field is required"
	case "email":
		return "Must be a valid email address"
	case "min":
		return fmt.Sprintf("Must be at least %s characters long", fe.Param())
	case "max":
		return fmt.Sprintf("Must be no more than %s characters long", fe.Param())
	case "len":
		return fmt.Sprintf("Must be exactly %s characters long", fe.Param())
	case "numeric":
		return "Must contain only numbers"
	case "url":
		return "Must be a valid URL"
	case "eqfield":
		return fmt.Sprintf("Must match %s", fe.Param())
	case "gt":
		return fmt.Sprintf("Must be greater than %s", fe.Param())
	case "gte":
		return fmt.Sprintf("Must be greater than or equal to %s", fe.Param())
	case "lt":
		return fmt.Sprintf("Must be less than %s", fe.Param())
	case "lte":
		return fmt.Sprintf("Must be less than or equal to %s", fe.Param())
	case "oneof":
		return fmt.Sprintf("Must be one of: %s", strings.ReplaceAll(fe.Param(), " ", ", "))
	default:
		return fmt.Sprintf("Invalid value for %s", fe.Field())
	}
}
