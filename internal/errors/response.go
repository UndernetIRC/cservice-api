// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2024 UnderNET

package errors

// ErrorResponse represents a structured error response
type ErrorResponse struct {
	Error struct {
		Code    string      `json:"code"`              // Error code constant
		Message string      `json:"message"`           // Human-readable message
		Details interface{} `json:"details,omitempty"` // Additional error details (validation errors, etc.)
	} `json:"error"`
	Status string `json:"status"` // Always "error"
}

// SuccessResponse represents a structured success response
type SuccessResponse struct {
	Data   interface{} `json:"data"`   // Response data
	Status string      `json:"status"` // Always "success"
}

// NewErrorResponse creates a new error response with the specified code, message, and details
func NewErrorResponse(code, message string, details interface{}) ErrorResponse {
	resp := ErrorResponse{
		Status: "error",
	}
	resp.Error.Code = code
	resp.Error.Message = message
	resp.Error.Details = details
	return resp
}

// NewSuccessResponse creates a new success response with the specified data
func NewSuccessResponse(data interface{}) SuccessResponse {
	return SuccessResponse{
		Data:   data,
		Status: "success",
	}
}
