// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2024 UnderNET

// Package errors provides consistent error handling and response formatting for the API
package errors

// Error codes for consistent error identification
const (
	ErrCodeValidation      = "VALIDATION_ERROR"
	ErrCodeDatabase        = "DATABASE_ERROR"
	ErrCodeUnauthorized    = "UNAUTHORIZED"
	ErrCodeForbidden       = "FORBIDDEN"
	ErrCodeNotFound        = "NOT_FOUND"
	ErrCodeConflict        = "CONFLICT"
	ErrCodeInternal        = "INTERNAL_ERROR"
	ErrCodeBadRequest      = "BAD_REQUEST"
	ErrCodeUnprocessable   = "UNPROCESSABLE_ENTITY"
	ErrCodeTooManyRequests = "TOO_MANY_REQUESTS"

	// Channel Registration specific error codes
	ErrCodeRegistrationsDisabled  = "REGISTRATIONS_DISABLED"
	ErrCodeUserRestricted         = "USER_RESTRICTED"
	ErrCodeIrcIdleCheckFailed     = "IRC_IDLE_CHECK_FAILED"
	ErrCodePendingExists          = "PENDING_REGISTRATION_EXISTS"
	ErrCodeChannelLimitExceeded   = "CHANNEL_LIMIT_EXCEEDED"
	ErrCodeChannelLimitReached    = "CHANNEL_LIMIT_REACHED"
	ErrCodeCooldownActive         = "COOLDOWN_ACTIVE"
	ErrCodeCooldownPeriod         = "COOLDOWN_PERIOD"
	ErrCodeInsufficientSupporters = "INSUFFICIENT_SUPPORTERS"
	ErrCodeInvalidChannelName     = "INVALID_CHANNEL_NAME"
	ErrCodeInvalidDescription     = "INVALID_DESCRIPTION"
	ErrCodeChannelNameExists      = "CHANNEL_NAME_EXISTS"
	ErrCodeChannelAlreadyExists   = "CHANNEL_ALREADY_EXISTS"
	ErrCodeInvalidSupporterUser   = "INVALID_SUPPORTER_USER"
	ErrCodeInvalidSupporters      = "INVALID_SUPPORTERS"
	ErrCodeSelfSupportNotAllowed  = "SELF_SUPPORT_NOT_ALLOWED"
	ErrCodeDuplicateSupporters    = "DUPLICATE_SUPPORTERS"
	ErrCodeInactiveUser           = "INACTIVE_USER"
	ErrCodeDatabaseError          = "DATABASE_ERROR"
)
