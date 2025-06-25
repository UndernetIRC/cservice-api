// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2024 UnderNET

package errors

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

// ManagerChangeErrorHandler provides specialized error handling for manager change operations
type ManagerChangeErrorHandler struct{}

// NewManagerChangeErrorHandler creates a new manager change error handler
func NewManagerChangeErrorHandler() *ManagerChangeErrorHandler {
	return &ManagerChangeErrorHandler{}
}

// HandleBusinessRuleError handles manager change business rule validation errors with proper HTTP status mapping
func (h *ManagerChangeErrorHandler) HandleBusinessRuleError(c echo.Context, err error) error {
	if validationErr, ok := err.(ValidationError); ok {
		statusCode := h.mapBusinessRuleErrorToHTTPStatus(validationErr.GetCode())
		return c.JSON(statusCode, NewErrorResponse(
			validationErr.GetCode(),
			validationErr.GetMessage(),
			validationErr.GetDetails(),
		))
	}

	// Fallback to generic internal error for unexpected business rule errors
	return HandleInternalError(c, err, "Manager change validation failed")
}

// mapBusinessRuleErrorToHTTPStatus maps business rule error codes to appropriate HTTP status codes
func (h *ManagerChangeErrorHandler) mapBusinessRuleErrorToHTTPStatus(errorCode string) int {
	switch errorCode {
	// Forbidden errors (403)
	case ErrCodeForbidden:
		return http.StatusForbidden

	// Not found errors (404)
	case ErrCodeNotFound:
		return http.StatusNotFound

	// Conflict errors (409)
	case ErrCodeConflict:
		return http.StatusConflict

	// Bad request errors (400)
	case ErrCodeBadRequest:
		return http.StatusBadRequest

	// Database errors (500)
	case ErrCodeDatabase:
		return http.StatusInternalServerError

	default:
		return http.StatusInternalServerError
	}
}

// GetErrorCategory categorizes errors for better error handling and monitoring
func (h *ManagerChangeErrorHandler) GetErrorCategory(errorCode string) string {
	switch errorCode {
	case ErrCodeForbidden:
		return "authorization"

	case ErrCodeNotFound:
		return "not_found"

	case ErrCodeConflict:
		return "business_rule"

	case ErrCodeBadRequest:
		return "validation"

	case ErrCodeDatabase:
		return "database"

	default:
		return "unknown"
	}
}

// IsRetryableError determines if an error condition might be resolved by retrying
func (h *ManagerChangeErrorHandler) IsRetryableError(errorCode string) bool {
	switch errorCode {
	case ErrCodeDatabase:
		return true
	default:
		return false
	}
}
