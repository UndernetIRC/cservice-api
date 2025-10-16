// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2024 UnderNET

package errors

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/labstack/echo/v4"
)

// ErrResponseSent is a sentinel error indicating the response has been sent
// This prevents further processing in handler chains
var ErrResponseSent = errors.New("response already sent")

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
// Special handling for unique constraint violations returns a conflict error
func HandleDatabaseError(c echo.Context, err error) error {
	requestID := getRequestID(c)

	// Check if this is a unique constraint violation
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		// This is a unique constraint violation
		// Try to extract meaningful constraint information
		message := "A record with this information already exists"

		// Parse constraint name to provide better error messages
		if strings.Contains(pgErr.ConstraintName, "username") {
			message = "Username already exists"
		} else if strings.Contains(pgErr.ConstraintName, "email") {
			message = "Email already exists"
		}

		slog.Warn("Unique constraint violation",
			"requestID", requestID,
			"path", c.Request().URL.Path,
			"method", c.Request().Method,
			"constraint", pgErr.ConstraintName,
			"detail", pgErr.Detail)

		// Send response but return sentinel error to stop further processing
		// This is needed for scenarios like user registration where we must prevent
		// duplicate operations (like sending emails) after a constraint violation
		_ = c.JSON(http.StatusConflict, NewErrorResponse(
			ErrCodeConflict,
			message,
			nil,
		))
		// Return ErrResponseSent to signal response was sent but processing should stop
		return ErrResponseSent
	}

	// Structured logging with slog for database errors
	slog.Error("Database error",
		"requestID", requestID,
		"path", c.Request().URL.Path,
		"method", c.Request().Method,
		"error", err.Error())

	// Return a generic error to the client
	// Return nil as per Echo convention - response has been sent
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

	// Send response but return sentinel error to stop further processing
	// This prevents duplicate operations (like creating pending users or sending emails)
	// after detecting a conflict
	_ = c.JSON(http.StatusConflict, NewErrorResponse(
		ErrCodeConflict,
		message,
		nil,
	))
	return ErrResponseSent
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
