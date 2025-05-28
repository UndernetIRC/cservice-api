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
	"github.com/undernetirc/cservice-api/internal/helper"
	"github.com/undernetirc/cservice-api/models"
)

type UserController struct {
	s models.Querier
}

func NewUserController(s models.Querier) *UserController {
	return &UserController{s: s}
}

type UserResponse struct {
	ID           int32                 `json:"id"                      extensions:"x-order=0"`
	Username     string                `json:"username"                extensions:"x-order=1"`
	Email        string                `json:"email,omitempty"         extensions:"x-order=2"`
	MaxLogins    int32                 `json:"max_logins"              extensions:"x-order=3"`
	LanguageCode string                `json:"language_code,omitempty" extensions:"x-order=4"`
	LanguageName string                `json:"language_name,omitempty" extensions:"x-order=5"`
	LastSeen     int32                 `json:"last_seen,omitempty"     extensions:"x-order=6"`
	TotpEnabled  bool                  `json:"totp_enabled"            extensions:"x-order=7"`
	Channels     []UserChannelResponse `json:"channels,omitempty"      extensions:"x-order=8"`
}

type UserChannelResponse struct {
	Name         string `json:"name"`
	ChannelID    int32  `json:"channel_id"`
	Access       int32  `json:"access"`
	LastModified int32  `json:"last_modified,omitempty"`
}

// GetUser returns a user by id
// @Summary Get user data by id
// @Description Returns a user by id
// @Tags users
// @Produce json
// @Param id path int true "User ID"
// @Success 200 {object} UserResponse
// @Router /users/{id} [get]
// @Security JWTBearerToken
func (ctr *UserController) GetUser(c echo.Context) error {
	id, err := helper.SafeAtoi32(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid user ID")
	}

	user, err := ctr.s.GetUser(c.Request().Context(), models.GetUserParams{ID: id})
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, fmt.Sprintf("User by id %d not found", id))
	}

	response := &UserResponse{}
	err = copier.Copy(&response, &user)
	if err != nil {
		c.Logger().Errorf("Failed to copy user to response DTO: %s", err.Error())
		return echo.NewHTTPError(http.StatusInternalServerError, "Internal server error")
	}
	response.TotpEnabled = user.Flags.HasFlag(flags.UserTotpEnabled)

	userChannels, err := ctr.s.GetUserChannels(c.Request().Context(), id)
	if err != nil {
		c.Logger().Errorf("Failed to fetch user channels: %s", err.Error())
	}

	err = copier.Copy(&response.Channels, &userChannels)
	if err != nil {
		c.Logger().Errorf("Failed to copy userChannels to response DTO: %s", err.Error())
		return echo.NewHTTPError(http.StatusInternalServerError, "Internal server error")
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
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid user ID")
	}

	user, err := ctr.s.GetUserByID(c.Request().Context(), id)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	roles, err := ctr.s.ListUserRoles(c.Request().Context(), id)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
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

func (ctr *UserController) GetUserChannels(c echo.Context) error {
	id, err := helper.SafeAtoi32(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid user ID")
	}

	userChannels, err := ctr.s.GetUserChannels(c.Request().Context(), id)
	if err != nil {
		c.Logger().Errorf("Failed to fetch user channels: %s", err.Error())
		return echo.NewHTTPError(http.StatusInternalServerError, "Internal server error")
	}

	return c.JSON(http.StatusOK, userChannels)
}

// GetCurrentUser returns detailed information about the current authenticated user
// @Summary Get current user information
// @Description Get current user information
// @Tags users
// @Accept json
// @Produce json
// @Success 200 {object} UserResponse
// @Failure 401 "Authorization information is missing or invalid."
// @Failure 404 "User not found."
// @Failure 500 "Internal server error."
// @Router /user [get]
// @Security JWTBearerToken
func (ctr *UserController) GetCurrentUser(c echo.Context) error {
	// Create a context with timeout for database operations
	ctx, cancel := context.WithTimeout(c.Request().Context(), 5*time.Second)
	defer cancel()

	// Get user claims from context
	claims := helper.GetClaimsFromContext(c)
	if claims == nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "Authorization information is missing or invalid")
	}

	// Fetch user data
	user, err := ctr.s.GetUserByID(ctx, claims.UserID)
	if err != nil {
		c.Logger().Errorf("Failed to fetch user by ID %d: %s", claims.UserID, err.Error())
		return echo.NewHTTPError(http.StatusNotFound, fmt.Sprintf("User with ID %d not found", claims.UserID))
	}

	// Create response and copy user data
	response := &UserResponse{}
	err = copier.Copy(&response, &user)
	if err != nil {
		c.Logger().Errorf("Failed to copy user to response DTO: %s", err.Error())
		return echo.NewHTTPError(http.StatusInternalServerError, "Internal server error")
	}

	// Set TOTP status
	response.TotpEnabled = user.Flags.HasFlag(flags.UserTotpEnabled)

	// Fetch user channels
	userChannels, err := ctr.s.GetUserChannels(ctx, claims.UserID)
	if err != nil {
		c.Logger().Errorf("Failed to fetch user channels: %s", err.Error())
		// Return partial response with empty channels instead of failing completely
		response.Channels = []UserChannelResponse{}
	} else {
		// Copy channel data to response
		err = copier.Copy(&response.Channels, &userChannels)
		if err != nil {
			c.Logger().Errorf("Failed to copy userChannels to response DTO: %s", err.Error())
			return echo.NewHTTPError(http.StatusInternalServerError, "Internal server error")
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
// @Tags users
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
	// Create a context with timeout for database operations
	ctx, cancel := context.WithTimeout(c.Request().Context(), 10*time.Second)
	defer cancel()

	// Get user claims from context
	claims := helper.GetClaimsFromContext(c)
	if claims == nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "Authorization information is missing or invalid")
	}

	// Bind and validate request
	req := new(ChangePasswordRequest)
	if err := c.Bind(req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request format")
	}

	if err := c.Validate(req); err != nil {
		c.Logger().Errorf("Validation error for user %d: %s", claims.UserID, err.Error())
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	// Fetch current user data to validate current password
	user, err := ctr.s.GetUserByUsername(ctx, claims.Username)
	if err != nil {
		c.Logger().Errorf("Failed to fetch user %s for password change: %s", claims.Username, err.Error())
		return echo.NewHTTPError(http.StatusNotFound, "User not found")
	}

	// Validate current password
	if err := user.Password.Validate(req.CurrentPassword); err != nil {
		c.Logger().Warnf("Invalid current password attempt for user %d (%s)", claims.UserID, claims.Username)
		return echo.NewHTTPError(http.StatusUnauthorized, "Current password is incorrect")
	}

	// Set new password (this will hash it automatically)
	if err := user.Password.Set(req.NewPassword); err != nil {
		c.Logger().Errorf("Failed to hash new password for user %d: %s", claims.UserID, err.Error())
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to process new password")
	}

	// Update password in database
	err = ctr.s.UpdateUserPassword(ctx, models.UpdateUserPasswordParams{
		ID:          claims.UserID,
		Password:    user.Password,
		LastUpdated: db.NewInt4(time.Now().Unix()).Int32,
	})
	if err != nil {
		c.Logger().Errorf("Failed to update password for user %d: %s", claims.UserID, err.Error())
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to update password")
	}

	c.Logger().Infof("Password successfully changed for user %d (%s)", claims.UserID, claims.Username)
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
// @Tags users
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
	// Create a context with timeout for database operations
	ctx, cancel := context.WithTimeout(c.Request().Context(), 5*time.Second)
	defer cancel()

	// Get user claims from context
	claims := helper.GetClaimsFromContext(c)
	if claims == nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "Authorization information is missing or invalid")
	}

	// Parse and validate request
	var req EnrollTOTPRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request format")
	}

	if err := c.Validate(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	// Get current user using GetUserByID which returns GetUserByIDRow
	user, err := ctr.s.GetUserByID(ctx, claims.UserID)
	if err != nil {
		c.Logger().Errorf("Failed to fetch user: %s", err.Error())
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to fetch user information")
	}

	// Check if 2FA is already enabled
	if user.Flags.HasFlag(flags.UserTotpEnabled) {
		return echo.NewHTTPError(http.StatusConflict, "2FA is already enabled")
	}

	// Validate current password
	if err := user.Password.Validate(req.CurrentPassword); err != nil {
		return echo.NewHTTPError(http.StatusForbidden, "Incorrect current password")
	}

	// Generate new TOTP secret
	otp := totp.New("", 6, 30, 0) // Empty seed generates random secret
	secret := otp.GetSeed()

	// Generate QR code
	qrCode, err := helper.GenerateTOTPQRCode(user.Username, secret)
	if err != nil {
		c.Logger().Errorf("Failed to generate QR code: %s", err.Error())
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to generate QR code")
	}

	// Store the secret temporarily (not activated yet)
	err = ctr.s.UpdateUserTotpKey(ctx, models.UpdateUserTotpKeyParams{
		ID:            claims.UserID,
		TotpKey:       db.NewString(secret),
		LastUpdated:   db.NewInt4(time.Now().Unix()).Int32,
		LastUpdatedBy: db.NewString(fmt.Sprintf("%d", claims.UserID)),
	})
	if err != nil {
		c.Logger().Errorf("Failed to store TOTP secret: %s", err.Error())
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to store 2FA configuration")
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
// @Tags users
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
	// Create a context with timeout for database operations
	ctx, cancel := context.WithTimeout(c.Request().Context(), 5*time.Second)
	defer cancel()

	// Get user claims from context
	claims := helper.GetClaimsFromContext(c)
	if claims == nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "Authorization information is missing or invalid")
	}

	// Parse and validate request
	var req ActivateTOTPRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request format")
	}

	if err := c.Validate(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	// Get current user
	user, err := ctr.s.GetUserByID(ctx, claims.UserID)
	if err != nil {
		c.Logger().Errorf("Failed to fetch user: %s", err.Error())
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to fetch user information")
	}

	// Check if 2FA is already enabled
	if user.Flags.HasFlag(flags.UserTotpEnabled) {
		return echo.NewHTTPError(http.StatusConflict, "2FA is already enabled")
	}

	// Check if user has enrolled (has a TOTP key)
	if !user.TotpKey.Valid || user.TotpKey.String == "" {
		return echo.NewHTTPError(http.StatusConflict, "2FA enrollment not started. Please enroll first.")
	}

	// Validate the provided OTP code
	totpInstance := totp.New(user.TotpKey.String, 6, 30, 0)
	valid := totpInstance.Validate(req.OTPCode)

	if !valid {
		return echo.NewHTTPError(http.StatusForbidden, "Invalid OTP code")
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
		c.Logger().Errorf("Failed to enable 2FA flag: %s", err.Error())
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to activate 2FA")
	}

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
// @Tags users
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
	// Create a context with timeout for database operations
	ctx, cancel := context.WithTimeout(c.Request().Context(), 5*time.Second)
	defer cancel()

	// Get user claims from context
	claims := helper.GetClaimsFromContext(c)
	if claims == nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "Authorization information is missing or invalid")
	}

	// Parse and validate request
	var req DisableTOTPRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request format")
	}

	if err := c.Validate(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	// Get current user
	user, err := ctr.s.GetUserByID(ctx, claims.UserID)
	if err != nil {
		c.Logger().Errorf("Failed to fetch user: %s", err.Error())
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to fetch user information")
	}

	// Check if 2FA is enabled
	if !user.Flags.HasFlag(flags.UserTotpEnabled) {
		return echo.NewHTTPError(http.StatusConflict, "2FA is not enabled")
	}

	// Validate current password
	if err := user.Password.Validate(req.CurrentPassword); err != nil {
		return echo.NewHTTPError(http.StatusForbidden, "Incorrect current password")
	}

	// Validate the provided OTP code if TOTP key exists
	if user.TotpKey.Valid && user.TotpKey.String != "" {
		totpInstance := totp.New(user.TotpKey.String, 6, 30, 0)
		valid := totpInstance.Validate(req.OTPCode)

		if !valid {
			return echo.NewHTTPError(http.StatusForbidden, "Invalid OTP code")
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
		c.Logger().Errorf("Failed to disable 2FA flag: %s", err.Error())
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to disable 2FA")
	}

	// Clear the TOTP key
	err = ctr.s.UpdateUserTotpKey(ctx, models.UpdateUserTotpKeyParams{
		ID:            claims.UserID,
		TotpKey:       db.NewString(""),
		LastUpdated:   db.NewInt4(time.Now().Unix()).Int32,
		LastUpdatedBy: db.NewString(fmt.Sprintf("%d", claims.UserID)),
	})
	if err != nil {
		c.Logger().Errorf("Failed to clear TOTP key: %s", err.Error())
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to clear 2FA configuration")
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "2FA disabled successfully"})
}
