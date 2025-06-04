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
)
