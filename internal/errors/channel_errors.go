// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2024 UnderNET

package errors

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

// ValidationError interface for validation errors that can be handled by the channel error handler
type ValidationError interface {
	Error() string
	GetCode() string
	GetMessage() string
	GetDetails() interface{}
}

// ChannelRegistrationErrorHandler provides specialized error handling for channel registration operations
type ChannelRegistrationErrorHandler struct{}

// NewChannelRegistrationErrorHandler creates a new channel registration error handler
func NewChannelRegistrationErrorHandler() *ChannelRegistrationErrorHandler {
	return &ChannelRegistrationErrorHandler{}
}

// HandleValidationError handles channel registration validation errors with proper HTTP status mapping
func (h *ChannelRegistrationErrorHandler) HandleValidationError(c echo.Context, err error) error {
	if validationErr, ok := err.(ValidationError); ok {
		statusCode := h.mapValidationErrorToHTTPStatus(validationErr.GetCode())
		return c.JSON(statusCode, NewErrorResponse(
			validationErr.GetCode(),
			validationErr.GetMessage(),
			validationErr.GetDetails(),
		))
	}

	// Fallback to generic internal error for unexpected validation errors
	return HandleInternalError(c, err, "Validation failed")
}

// HandleBusinessRuleError handles business rule validation errors with proper HTTP status mapping
func (h *ChannelRegistrationErrorHandler) HandleBusinessRuleError(c echo.Context, err error) error {
	if validationErr, ok := err.(ValidationError); ok {
		statusCode := h.mapBusinessRuleErrorToHTTPStatus(validationErr.GetCode())
		return c.JSON(statusCode, NewErrorResponse(
			validationErr.GetCode(),
			validationErr.GetMessage(),
			validationErr.GetDetails(),
		))
	}

	// Fallback to generic internal error for unexpected business rule errors
	return HandleInternalError(c, err, "Business rule validation failed")
}

// mapValidationErrorToHTTPStatus maps validation error codes to appropriate HTTP status codes
func (h *ChannelRegistrationErrorHandler) mapValidationErrorToHTTPStatus(errorCode string) int {
	switch errorCode {
	case ErrCodeInvalidChannelName, ErrCodeInvalidDescription, ErrCodeInsufficientSupporters,
		ErrCodeInvalidSupporters, ErrCodeDuplicateSupporters:
		return http.StatusBadRequest
	case ErrCodeSelfSupportNotAllowed:
		return http.StatusUnprocessableEntity
	default:
		return http.StatusBadRequest
	}
}

// mapBusinessRuleErrorToHTTPStatus maps business rule error codes to appropriate HTTP status codes
func (h *ChannelRegistrationErrorHandler) mapBusinessRuleErrorToHTTPStatus(errorCode string) int {
	switch errorCode {
	// User restriction errors (403 Forbidden)
	case ErrCodeUserRestricted, ErrCodeIrcIdleCheckFailed, ErrCodeInactiveUser:
		return http.StatusForbidden

	// Resource conflict errors (409 Conflict)
	case ErrCodePendingExists, ErrCodeChannelLimitExceeded, ErrCodeChannelLimitReached,
		ErrCodeCooldownActive, ErrCodeCooldownPeriod, ErrCodeChannelNameExists,
		ErrCodeChannelAlreadyExists:
		return http.StatusConflict

	// Service unavailable errors (503 Service Unavailable)
	case ErrCodeRegistrationsDisabled:
		return http.StatusServiceUnavailable

	// Validation-like errors that should be 400
	case ErrCodeInvalidSupporterUser:
		return http.StatusBadRequest

	default:
		return http.StatusBadRequest
	}
}

// GetErrorCategory categorizes errors for better error handling and monitoring
func (h *ChannelRegistrationErrorHandler) GetErrorCategory(errorCode string) string {
	switch errorCode {
	case ErrCodeInvalidChannelName, ErrCodeInvalidDescription, ErrCodeInsufficientSupporters,
		ErrCodeInvalidSupporters, ErrCodeDuplicateSupporters, ErrCodeSelfSupportNotAllowed,
		ErrCodeInvalidSupporterUser:
		return "validation"

	case ErrCodeUserRestricted, ErrCodeIrcIdleCheckFailed, ErrCodeInactiveUser:
		return "authorization"

	case ErrCodePendingExists, ErrCodeChannelLimitExceeded, ErrCodeChannelLimitReached,
		ErrCodeCooldownActive, ErrCodeCooldownPeriod, ErrCodeChannelNameExists,
		ErrCodeChannelAlreadyExists:
		return "business_rule"

	case ErrCodeRegistrationsDisabled:
		return "service_availability"

	case ErrCodeDatabaseError:
		return "database"

	default:
		return "unknown"
	}
}

// IsRetryableError determines if an error condition might be resolved by retrying
func (h *ChannelRegistrationErrorHandler) IsRetryableError(errorCode string) bool {
	switch errorCode {
	case ErrCodeDatabaseError:
		return true
	case ErrCodeRegistrationsDisabled:
		return true // Service might become available later
	default:
		return false
	}
}

// GetUserFriendlyMessage provides user-friendly error messages for common error scenarios
func (h *ChannelRegistrationErrorHandler) GetUserFriendlyMessage(errorCode string) string {
	switch errorCode {
	case ErrCodeInvalidChannelName:
		return "The channel name is invalid. Channel names must start with # and contain only valid IRC characters."
	case ErrCodeInvalidDescription:
		return "The channel description is invalid. Please provide a description between 1 and 300 characters."
	case ErrCodeInsufficientSupporters:
		return "You need at least one supporter to register a channel."
	case ErrCodeSelfSupportNotAllowed:
		return "You cannot support your own channel registration."
	case ErrCodeDuplicateSupporters:
		return "Each supporter can only be listed once."
	case ErrCodeUserRestricted:
		return "Your account is restricted from registering channels. Please contact support."
	case ErrCodeIrcIdleCheckFailed:
		return "You must be active on IRC to register a channel."
	case ErrCodeChannelLimitExceeded:
		return "You have reached the maximum number of channels you can register."
	case ErrCodeCooldownActive:
		return "You must wait before registering another channel."
	case ErrCodeChannelNameExists:
		return "A channel with this name already exists."
	case ErrCodePendingExists:
		return "You already have a pending channel registration."
	case ErrCodeRegistrationsDisabled:
		return "Channel registrations are temporarily disabled. Please try again later."
	default:
		return "An error occurred while processing your channel registration."
	}
}
