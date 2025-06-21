// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package controllers

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/jinzhu/copier"
	"github.com/labstack/echo/v4"

	"github.com/undernetirc/cservice-api/db"
	"github.com/undernetirc/cservice-api/db/types/flags"
	"github.com/undernetirc/cservice-api/internal/auth/oath/totp"
	apierrors "github.com/undernetirc/cservice-api/internal/errors"
	"github.com/undernetirc/cservice-api/internal/helper"
	"github.com/undernetirc/cservice-api/models"
)

type UserController struct {
	s models.Querier
}

func NewUserController(s models.Querier) *UserController {
	return &UserController{s: s}
}

// ChannelMembership represents channel membership information with enhanced details
type ChannelMembership struct {
	ChannelID   int32  `json:"channel_id"`
	ChannelName string `json:"channel_name"`
	AccessLevel int32  `json:"access_level"`
	MemberCount int64  `json:"member_count"`
	JoinedAt    int32  `json:"joined_at"`
}

// UserResponse represents the user response with detailed channel membership information
type UserResponse struct {
	ID           int32               `json:"id"                      extensions:"x-order=0"`
	Username     string              `json:"username"                extensions:"x-order=1"`
	Email        string              `json:"email,omitempty"         extensions:"x-order=2"`
	MaxLogins    int32               `json:"max_logins"              extensions:"x-order=3"`
	LanguageCode string              `json:"language_code,omitempty" extensions:"x-order=4"`
	LanguageName string              `json:"language_name,omitempty" extensions:"x-order=5"`
	LastSeen     int32               `json:"last_seen,omitempty"     extensions:"x-order=6"`
	TotpEnabled  bool                `json:"totp_enabled"            extensions:"x-order=7"`
	Channels     []ChannelMembership `json:"channels,omitempty"      extensions:"x-order=8"`
}

// GetUser returns a user by id
// @Summary Get user data by id
// @Description Returns a user by id with detailed channel membership information
// @Tags users
// @Produce json
// @Param id path int true "User ID"
// @Success 200 {object} UserResponse
// @Router /users/{id} [get]
// @Security JWTBearerToken
func (ctr *UserController) GetUser(c echo.Context) error {
	logger := helper.GetRequestLogger(c)

	id, err := helper.SafeAtoi32(c.Param("id"))
	if err != nil {
		return apierrors.HandleBadRequestError(c, "Invalid user ID")
	}

	user, err := ctr.s.GetUser(c.Request().Context(), models.GetUserParams{ID: id})
	if err != nil {
		return apierrors.HandleNotFoundError(c, fmt.Sprintf("User with ID %d", id))
	}

	response := &UserResponse{}
	err = copier.Copy(&response, &user)
	if err != nil {
		logger.Error("Failed to copy user to response DTO",
			"userID", id,
			"error", err.Error())
		return apierrors.HandleInternalError(c, err, "Failed to process user data")
	}
	response.TotpEnabled = user.Flags.HasFlag(flags.UserTotpEnabled)

	// Fetch enhanced channel membership data
	channelMemberships, err := ctr.s.GetUserChannelMemberships(c.Request().Context(), id)
	if err != nil {
		logger.Error("Failed to fetch user channel memberships",
			"userID", id,
			"error", err.Error())
		// Return partial response with empty channels instead of failing completely
		response.Channels = []ChannelMembership{}
	} else {
		// Convert SQLC result to response format
		response.Channels = make([]ChannelMembership, len(channelMemberships))
		for i, membership := range channelMemberships {
			response.Channels[i] = ChannelMembership{
				ChannelID:   membership.ChannelID,
				ChannelName: membership.ChannelName,
				AccessLevel: membership.AccessLevel,
				MemberCount: membership.MemberCount,
				JoinedAt:    db.Int4ToInt32(membership.JoinedAt),
			}
		}
	}

	return c.JSON(http.StatusOK, response)
}

type UserRolesResponse struct {
	User struct {
		ID       int32  `json:"id" extensions:"x-order=0"`
		Username string `json:"username" extensions:"x-order=1"`
		Roles    []Role `json:"roles" extensions:"x-order=1"`
	} `json:"user" extensions:"x-order=0"`
}

type Role struct {
	ID          int32  `json:"id"          extensions:"x-order=0"`
	Name        string `json:"name"        extensions:"x-order=1"`
	Description string `json:"description" extensions:"x-order=2"`
}

// GetUserRoles returns the roles for a given user
// @Summary Get the roles for a given user
// @Description Get the roles for a given user
// @Tags users
// @Produce json
// @Param id path int true "User ID"
// @Success 200 {object} UserRolesResponse
// @Failure 400 {string} string "Invalid user ID"
// @Failure 404 {string} string "User not found"
// @Failure 500 {string} string "Internal server error"
// @Router /users/{id}/roles [get]
// @Security JWTBearerToken
func (ctr *UserController) GetUserRoles(c echo.Context) error {
	id, err := helper.SafeAtoi32(c.Param("id"))
	if err != nil {
		return apierrors.HandleBadRequestError(c, "Invalid user ID")
	}

	user, err := ctr.s.GetUser(c.Request().Context(), models.GetUserParams{
		ID: id,
	})
	if err != nil {
		return apierrors.HandleDatabaseError(c, err)
	}

	roles, err := ctr.s.ListUserRoles(c.Request().Context(), id)
	if err != nil {
		return apierrors.HandleDatabaseError(c, err)
	}

	resp := new(UserRolesResponse)
	resp.User.ID = user.ID
	resp.User.Username = user.Username
	for _, role := range roles {
		resp.User.Roles = append(resp.User.Roles, Role{
			ID:          role.ID,
			Name:        role.Name,
			Description: role.Description,
		})
	}

	return c.JSON(http.StatusOK, resp)
}

// GetUserChannels returns detailed channel membership information for a user
// @Summary Get user's channel memberships
// @Description Returns detailed channel membership information for a user including member counts
// @Tags users
// @Produce json
// @Param id path int true "User ID"
// @Success 200 {array} ChannelMembership
// @Failure 400 "Invalid user ID"
// @Failure 500 "Internal server error"
// @Router /users/{id}/channels [get]
// @Security JWTBearerToken
func (ctr *UserController) GetUserChannels(c echo.Context) error {
	id, err := helper.SafeAtoi32(c.Param("id"))
	if err != nil {
		return apierrors.HandleBadRequestError(c, "Invalid user ID")
	}

	// Fetch enhanced channel membership data
	channelMemberships, err := ctr.s.GetUserChannelMemberships(c.Request().Context(), id)
	if err != nil {
		return apierrors.HandleDatabaseError(c, err)
	}

	// Convert SQLC result to response format
	channels := make([]ChannelMembership, len(channelMemberships))
	for i, membership := range channelMemberships {
		channels[i] = ChannelMembership{
			ChannelID:   membership.ChannelID,
			ChannelName: membership.ChannelName,
			AccessLevel: membership.AccessLevel,
			MemberCount: membership.MemberCount,
			JoinedAt:    db.Int4ToInt32(membership.JoinedAt),
		}
	}

	return c.JSON(http.StatusOK, channels)
}

// GetCurrentUser returns detailed information about the current authenticated user
// @Summary Get current user information
// @Description Get current user information with detailed channel membership data
// @Description Performance: Uses optimized single-query approach to avoid N+1 problems
// @Tags user
// @Accept json
// @Produce json
// @Success 200 {object} UserResponse
// @Failure 401 "Authorization information is missing or invalid."
// @Failure 404 "User not found."
// @Failure 500 "Internal server error."
// @Router /user [get]
// @Security JWTBearerToken
func (ctr *UserController) GetCurrentUser(c echo.Context) error {
	logger := helper.GetRequestLogger(c)

	// Create a context with timeout for database operations
	ctx, cancel := context.WithTimeout(c.Request().Context(), 5*time.Second)
	defer cancel()

	// Get user claims from context
	claims := helper.GetClaimsFromContext(c)
	if claims == nil {
		return apierrors.HandleUnauthorizedError(c, "Authorization information is missing or invalid")
	}

	// Fetch user data
	user, err := ctr.s.GetUser(ctx, models.GetUserParams{
		ID: claims.UserID,
	})
	if err != nil {
		logger.Error("Failed to fetch user by ID",
			"userID", claims.UserID,
			"error", err.Error())
		return apierrors.HandleNotFoundError(c, fmt.Sprintf("User with ID %d", claims.UserID))
	}

	// Create enhanced response
	response := &UserResponse{}
	err = copier.Copy(&response, &user)
	if err != nil {
		logger.Error("Failed to copy user to response DTO",
			"userID", claims.UserID,
			"error", err.Error())
		return apierrors.HandleInternalError(c, err, "Failed to process user data")
	}

	// Set TOTP status
	response.TotpEnabled = user.Flags.HasFlag(flags.UserTotpEnabled)

	// Fetch enhanced channel membership data
	channelMemberships, err := ctr.s.GetUserChannelMemberships(ctx, claims.UserID)
	if err != nil {
		logger.Error("Failed to fetch user channel memberships",
			"userID", claims.UserID,
			"error", err.Error())
		// Return partial response with empty channels instead of failing completely
		response.Channels = []ChannelMembership{}
	} else {
		// Convert SQLC result to response format
		response.Channels = make([]ChannelMembership, len(channelMemberships))
		for i, membership := range channelMemberships {
			response.Channels[i] = ChannelMembership{
				ChannelID:   membership.ChannelID,
				ChannelName: membership.ChannelName,
				AccessLevel: membership.AccessLevel,
				MemberCount: membership.MemberCount,
				JoinedAt:    db.Int4ToInt32(membership.JoinedAt),
			}
		}
	}

	return c.JSON(http.StatusOK, response)
}

// ChangePasswordRequest defines the request payload for changing password
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" validate:"required,max=72"              extensions:"x-order=0"`
	NewPassword     string `json:"new_password"     validate:"required,min=10,max=72"       extensions:"x-order=1"`
	ConfirmPassword string `json:"confirm_password" validate:"required,eqfield=NewPassword" extensions:"x-order=2"`
}

// ChangePassword allows an authenticated user to change their password
// @Summary Change user password
// @Description Changes the password for the currently authenticated user
// @Tags user
// @Accept json
// @Produce json
// @Param data body ChangePasswordRequest true "Password change request"
// @Success 200 {string} string "Password changed successfully"
// @Failure 400 {string} string "Bad request - validation error"
// @Failure 401 {string} string "Unauthorized - invalid current password"
// @Failure 404 {string} string "User not found"
// @Failure 500 {string} string "Internal server error"
// @Router /user/password [put]
// @Security JWTBearerToken
func (ctr *UserController) ChangePassword(c echo.Context) error {
	logger := helper.GetRequestLogger(c)

	// Create a context with timeout for database operations
	ctx, cancel := context.WithTimeout(c.Request().Context(), 10*time.Second)
	defer cancel()

	// Get user claims from context
	claims := helper.GetClaimsFromContext(c)
	if claims == nil {
		return apierrors.HandleUnauthorizedError(c, "Authorization information is missing or invalid")
	}

	// Bind and validate request
	req := new(ChangePasswordRequest)
	if err := c.Bind(req); err != nil {
		return apierrors.HandleBadRequestError(c, "Invalid request format")
	}

	if err := c.Validate(req); err != nil {
		return apierrors.HandleValidationError(c, err)
	}

	// Fetch current user data to validate current password
	user, err := ctr.s.GetUser(ctx, models.GetUserParams{
		Username: claims.Username,
	})
	if err != nil {
		logger.Error("Failed to fetch user for password change",
			"username", claims.Username,
			"userID", claims.UserID,
			"error", err.Error())
		return apierrors.HandleNotFoundError(c, "User")
	}

	// Validate current password
	if err := user.Password.Validate(req.CurrentPassword); err != nil {
		logger.Warn("Invalid current password attempt",
			"userID", claims.UserID,
			"username", claims.Username)
		return apierrors.HandleUnauthorizedError(c, "Current password is incorrect")
	}

	// Set new password (this will hash it automatically)
	if err := user.Password.Set(req.NewPassword); err != nil {
		logger.Error("Failed to hash new password",
			"userID", claims.UserID,
			"error", err.Error())
		return apierrors.HandleInternalError(c, err, "Failed to process new password")
	}

	// Update password in database
	err = ctr.s.UpdateUserPassword(ctx, models.UpdateUserPasswordParams{
		ID:          claims.UserID,
		Password:    user.Password,
		LastUpdated: db.NewInt4(time.Now().Unix()).Int32,
	})
	if err != nil {
		logger.Error("Failed to update password in database",
			"userID", claims.UserID,
			"error", err.Error())
		return apierrors.HandleDatabaseError(c, err)
	}

	logger.Info("Password successfully changed",
		"userID", claims.UserID,
		"username", claims.Username)

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Password changed successfully",
	})
}

// EnrollTOTPRequest defines the request payload for 2FA enrollment
type EnrollTOTPRequest struct {
	CurrentPassword string `json:"current_password" validate:"required,max=72" extensions:"x-order=0"`
}

// EnrollTOTPResponse defines the response for 2FA enrollment
type EnrollTOTPResponse struct {
	QRCodeBase64 string `json:"qr_code_base64" extensions:"x-order=0"`
	Secret       string `json:"secret"         extensions:"x-order=1"`
}

// EnrollTOTP allows an authenticated user to start 2FA enrollment by generating a QR code
// @Summary Start 2FA enrollment
// @Description Generates a QR code and secret for TOTP 2FA enrollment. Requires current password for security.
// @Tags user
// @Accept json
// @Produce json
// @Param data body EnrollTOTPRequest true "Password confirmation for 2FA enrollment"
// @Success 200 {object} EnrollTOTPResponse
// @Failure 400 "Bad request - validation failed"
// @Failure 401 "Unauthorized - missing or invalid token"
// @Failure 403 "Forbidden - incorrect password"
// @Failure 409 "Conflict - 2FA already enabled"
// @Failure 500 "Internal server error"
// @Router /user/2fa/enroll [post]
// @Security JWTBearerToken
func (ctr *UserController) EnrollTOTP(c echo.Context) error {
	logger := helper.GetRequestLogger(c)

	// Create a context with timeout for database operations
	ctx, cancel := context.WithTimeout(c.Request().Context(), 5*time.Second)
	defer cancel()

	// Get user claims from context
	claims := helper.GetClaimsFromContext(c)
	if claims == nil {
		return apierrors.HandleUnauthorizedError(c, "Authorization information is missing or invalid")
	}

	// Parse and validate request
	var req EnrollTOTPRequest
	if err := c.Bind(&req); err != nil {
		return apierrors.HandleBadRequestError(c, "Invalid request format")
	}

	if err := c.Validate(&req); err != nil {
		return apierrors.HandleValidationError(c, err)
	}

	// Get current user using GetUserByID which returns GetUserByIDRow
	user, err := ctr.s.GetUser(ctx, models.GetUserParams{
		ID: claims.UserID,
	})
	if err != nil {
		logger.Error("Failed to fetch user for 2FA enrollment",
			"userID", claims.UserID,
			"error", err.Error())
		return apierrors.HandleDatabaseError(c, err)
	}

	// Check if 2FA is already enabled
	if user.Flags.HasFlag(flags.UserTotpEnabled) {
		return apierrors.HandleConflictError(c, "2FA is already enabled")
	}

	// Validate current password
	if err := user.Password.Validate(req.CurrentPassword); err != nil {
		logger.Warn("Invalid current password attempt during 2FA enrollment",
			"userID", claims.UserID,
			"username", claims.Username)
		return apierrors.HandleForbiddenError(c, "Incorrect current password")
	}

	// Generate new TOTP secret
	otp := totp.New("", 6, 30, 0) // Empty seed generates random secret
	secret := otp.GetSeed()

	// Generate QR code
	qrCode, err := helper.GenerateTOTPQRCode(user.Username, secret)
	if err != nil {
		logger.Error("Failed to generate QR code for 2FA enrollment",
			"userID", claims.UserID,
			"error", err.Error())
		return apierrors.HandleInternalError(c, err, "Failed to generate QR code")
	}

	// Store the secret temporarily (not activated yet)
	err = ctr.s.UpdateUserTotpKey(ctx, models.UpdateUserTotpKeyParams{
		ID:            claims.UserID,
		TotpKey:       db.NewString(secret),
		LastUpdated:   db.NewInt4(time.Now().Unix()).Int32,
		LastUpdatedBy: db.NewString(fmt.Sprintf("%d", claims.UserID)),
	})
	if err != nil {
		logger.Error("Failed to store TOTP secret",
			"userID", claims.UserID,
			"error", err.Error())
		return apierrors.HandleDatabaseError(c, err)
	}

	response := EnrollTOTPResponse{
		QRCodeBase64: qrCode,
		Secret:       secret,
	}

	return c.JSON(http.StatusOK, response)
}

// ActivateTOTPRequest defines the request payload for 2FA activation
type ActivateTOTPRequest struct {
	OTPCode string `json:"otp_code" validate:"required,len=6,numeric" extensions:"x-order=0"`
}

// ActivateTOTP completes 2FA enrollment by validating the provided OTP code
// @Summary Complete 2FA enrollment
// @Description Validates the OTP code and activates 2FA for the user account
// @Tags user
// @Accept json
// @Produce json
// @Param data body ActivateTOTPRequest true "OTP code for 2FA activation"
// @Success 200 "2FA activated successfully"
// @Failure 400 "Bad request - validation failed"
// @Failure 401 "Unauthorized - missing or invalid token"
// @Failure 403 "Forbidden - invalid OTP code"
// @Failure 409 "Conflict - 2FA already enabled or not enrolled"
// @Failure 500 "Internal server error"
// @Router /user/2fa/activate [post]
// @Security JWTBearerToken
func (ctr *UserController) ActivateTOTP(c echo.Context) error {
	logger := helper.GetRequestLogger(c)

	// Create a context with timeout for database operations
	ctx, cancel := context.WithTimeout(c.Request().Context(), 5*time.Second)
	defer cancel()

	// Get user claims from context
	claims := helper.GetClaimsFromContext(c)
	if claims == nil {
		return apierrors.HandleUnauthorizedError(c, "Authorization information is missing or invalid")
	}

	// Parse and validate request
	var req ActivateTOTPRequest
	if err := c.Bind(&req); err != nil {
		return apierrors.HandleBadRequestError(c, "Invalid request format")
	}

	if err := c.Validate(&req); err != nil {
		return apierrors.HandleValidationError(c, err)
	}

	// Get current user
	user, err := ctr.s.GetUser(ctx, models.GetUserParams{
		ID: claims.UserID,
	})
	if err != nil {
		logger.Error("Failed to fetch user for 2FA activation",
			"userID", claims.UserID,
			"error", err.Error())
		return apierrors.HandleDatabaseError(c, err)
	}

	// Check if 2FA is already enabled
	if user.Flags.HasFlag(flags.UserTotpEnabled) {
		return apierrors.HandleConflictError(c, "2FA is already enabled")
	}

	// Check if user has enrolled (has a TOTP key)
	if !user.TotpKey.Valid || user.TotpKey.String == "" {
		return apierrors.HandleConflictError(c, "2FA enrollment not started. Please enroll first.")
	}

	// Validate the provided OTP code
	totpInstance := totp.New(user.TotpKey.String, 6, 30, 0)
	valid := totpInstance.Validate(req.OTPCode)

	if !valid {
		logger.Warn("Invalid OTP code attempt during 2FA activation",
			"userID", claims.UserID,
			"username", claims.Username)
		return apierrors.HandleForbiddenError(c, "Invalid OTP code")
	}

	// Enable 2FA flag
	user.Flags.AddFlag(flags.UserTotpEnabled)
	err = ctr.s.UpdateUserFlags(ctx, models.UpdateUserFlagsParams{
		ID:            claims.UserID,
		Flags:         user.Flags,
		LastUpdated:   db.NewInt4(time.Now().Unix()).Int32,
		LastUpdatedBy: db.NewString(fmt.Sprintf("%d", claims.UserID)),
	})
	if err != nil {
		logger.Error("Failed to enable 2FA flag",
			"userID", claims.UserID,
			"error", err.Error())
		return apierrors.HandleDatabaseError(c, err)
	}

	logger.Info("2FA successfully activated",
		"userID", claims.UserID,
		"username", claims.Username)

	return c.JSON(http.StatusOK, map[string]string{"message": "2FA activated successfully"})
}

// DisableTOTPRequest defines the request payload for 2FA disabling
type DisableTOTPRequest struct {
	CurrentPassword string `json:"current_password" validate:"required,max=72"        extensions:"x-order=0"`
	OTPCode         string `json:"otp_code"         validate:"required,len=6,numeric" extensions:"x-order=1"`
}

// DisableTOTP disables 2FA for the authenticated user
// @Summary Disable 2FA
// @Description Disables 2FA for the user account. Requires both current password and valid OTP code for security.
// @Tags user
// @Accept json
// @Produce json
// @Param data body DisableTOTPRequest true "Password and OTP code for 2FA disabling"
// @Success 200 "2FA disabled successfully"
// @Failure 400 "Bad request - validation failed"
// @Failure 401 "Unauthorized - missing or invalid token"
// @Failure 403 "Forbidden - incorrect password or invalid OTP"
// @Failure 409 "Conflict - 2FA is not enabled"
// @Failure 500 "Internal server error"
// @Router /user/2fa/disable [post]
// @Security JWTBearerToken
func (ctr *UserController) DisableTOTP(c echo.Context) error {
	logger := helper.GetRequestLogger(c)

	// Create a context with timeout for database operations
	ctx, cancel := context.WithTimeout(c.Request().Context(), 5*time.Second)
	defer cancel()

	// Get user claims from context
	claims := helper.GetClaimsFromContext(c)
	if claims == nil {
		return apierrors.HandleUnauthorizedError(c, "Authorization information is missing or invalid")
	}

	// Parse and validate request
	var req DisableTOTPRequest
	if err := c.Bind(&req); err != nil {
		return apierrors.HandleBadRequestError(c, "Invalid request format")
	}

	if err := c.Validate(&req); err != nil {
		return apierrors.HandleValidationError(c, err)
	}

	// Get current user
	user, err := ctr.s.GetUser(ctx, models.GetUserParams{
		ID: claims.UserID,
	})
	if err != nil {
		logger.Error("Failed to fetch user for 2FA disabling",
			"userID", claims.UserID,
			"error", err.Error())
		return apierrors.HandleDatabaseError(c, err)
	}

	// Check if 2FA is enabled
	if !user.Flags.HasFlag(flags.UserTotpEnabled) {
		return apierrors.HandleConflictError(c, "2FA is not enabled")
	}

	// Validate current password
	if err := user.Password.Validate(req.CurrentPassword); err != nil {
		logger.Warn("Invalid current password attempt during 2FA disabling",
			"userID", claims.UserID,
			"username", claims.Username)
		return apierrors.HandleForbiddenError(c, "Incorrect current password")
	}

	// Validate the provided OTP code if TOTP key exists
	if user.TotpKey.Valid && user.TotpKey.String != "" {
		totpInstance := totp.New(user.TotpKey.String, 6, 30, 0)
		valid := totpInstance.Validate(req.OTPCode)

		if !valid {
			logger.Warn("Invalid OTP code attempt during 2FA disabling",
				"userID", claims.UserID,
				"username", claims.Username)
			return apierrors.HandleForbiddenError(c, "Invalid OTP code")
		}
	}

	// Remove 2FA flag
	user.Flags.RemoveFlag(flags.UserTotpEnabled)
	err = ctr.s.UpdateUserFlags(ctx, models.UpdateUserFlagsParams{
		ID:            claims.UserID,
		Flags:         user.Flags,
		LastUpdated:   db.NewInt4(time.Now().Unix()).Int32,
		LastUpdatedBy: db.NewString(fmt.Sprintf("%d", claims.UserID)),
	})
	if err != nil {
		logger.Error("Failed to disable 2FA flag",
			"userID", claims.UserID,
			"error", err.Error())
		return apierrors.HandleDatabaseError(c, err)
	}

	// Clear the TOTP key
	err = ctr.s.UpdateUserTotpKey(ctx, models.UpdateUserTotpKeyParams{
		ID:            claims.UserID,
		TotpKey:       db.NewString(""),
		LastUpdated:   db.NewInt4(time.Now().Unix()).Int32,
		LastUpdatedBy: db.NewString(fmt.Sprintf("%d", claims.UserID)),
	})
	if err != nil {
		logger.Error("Failed to clear TOTP key",
			"userID", claims.UserID,
			"error", err.Error())
		return apierrors.HandleDatabaseError(c, err)
	}

	logger.Info("2FA successfully disabled",
		"userID", claims.UserID,
		"username", claims.Username)

	return c.JSON(http.StatusOK, map[string]string{"message": "2FA disabled successfully"})
}
