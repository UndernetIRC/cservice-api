// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023-2024 UnderNET

// Package controllers provides the controllers for the API
package controllers

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/labstack/echo/v4"
	"github.com/labstack/gommon/random"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/undernetirc/cservice-api/db/types/flags"
	"github.com/undernetirc/cservice-api/internal/auth/backupcodes"
	"github.com/undernetirc/cservice-api/internal/auth/oath/totp"
	"github.com/undernetirc/cservice-api/internal/auth/reset"
	"github.com/undernetirc/cservice-api/internal/checks"
	"github.com/undernetirc/cservice-api/internal/config"
	apierrors "github.com/undernetirc/cservice-api/internal/errors"
	"github.com/undernetirc/cservice-api/internal/helper"
	"github.com/undernetirc/cservice-api/internal/mail"
	"github.com/undernetirc/cservice-api/internal/tracing"
	"github.com/undernetirc/cservice-api/models"
)

// AuthenticationController is the controller for the authentication routes
type AuthenticationController struct {
	s            models.Querier
	rdb          *redis.Client
	clock        func() time.Time
	tokenManager *reset.TokenManager
}

// now returns the current time, or the time set by the clock func
// this function provides a way to mock the time in tests
func (ctr *AuthenticationController) now() time.Time {
	if ctr.clock == nil {
		return time.Now()
	}
	return ctr.clock()
}

// NewAuthenticationController returns a new AuthenticationController
func NewAuthenticationController(
	s models.Querier,
	rdb *redis.Client,
	t func() time.Time,
) *AuthenticationController {
	// Load password reset configuration
	resetConfig, err := reset.LoadConfigFromViper()
	if err != nil {
		// Use default config if loading fails
		defaultConfig := reset.DefaultConfig()
		resetConfig = &defaultConfig
	}

	// Create token manager
	tokenManager := reset.NewTokenManager(s, resetConfig)

	if t != nil {
		return &AuthenticationController{s: s, rdb: rdb, clock: t, tokenManager: tokenManager}
	}
	return &AuthenticationController{s: s, rdb: rdb, tokenManager: tokenManager}
}

// loginRequest is the struct holding the data for the login request
type loginRequest struct {
	Username string `json:"username" validate:"required,min=2,max=12" extensions:"x-order=0"`
	Password string `json:"password" validate:"required,max=72"       extensions:"x-order=1"`
}

// LoginResponse is the response sent to a client upon successful FULL authentication
type LoginResponse struct {
	AccessToken  string `json:"access_token"            extensions:"x-order=0" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"`
	RefreshToken string `json:"refresh_token,omitempty" extensions:"x-order=1" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"`
}

// loginStateResponse is the response sent to the client when an additional authentication factor is required
type loginStateResponse struct {
	StateToken string    `json:"state_token" extensions:"x-order=0"`
	ExpiresAt  time.Time `json:"expires_at"  extensions:"x-order=1"`
	Status     string    `json:"status"      extensions:"x-order=2"`
}

// Login godoc
// @Summary Login
// @Description Authenticates a user and returns an authentication token, which can be a JWT token or a state token.
// @Description If the user has enabled multi-factor authentication (MFA), a state token will be returned instead of a JWT token.
// @Description The state token is used in conjunction with the OTP (one-time password) to retrieve the actual JWT token.
// @Description To obtain the JWT token, the state token and OTP must be sent to the `/authn/verify_factor` endpoint.
// @Tags auth
// @Accept json
// @Produce json
// @Param data body loginRequest true "Login request"
// @Success 200 {object} LoginResponse
// @Failure 401 {object} errors.ErrorResponse "Invalid username or password"
// @Router /login [post]
func (ctr *AuthenticationController) Login(c echo.Context) error {
	logger := helper.GetRequestLogger(c)

	req := new(loginRequest)
	if err := c.Bind(req); err != nil {
		logger.Error("Failed to bind login request",
			"error", err.Error())
		return apierrors.HandleBadRequestError(c, "Invalid request format")
	}

	if err := c.Validate(req); err != nil {
		return apierrors.HandleValidationError(c, err)
	}

	// Start tracing for the entire login operation
	return tracing.TraceAuthentication(c.Request().Context(), req.Username, "login", func(ctx context.Context) error {
		// Trace credential validation stage
		var user models.GetUserRow
		err := tracing.TraceOperation(ctx, "validate_credentials", func(ctx context.Context) error {
			// Add detailed attributes for credential validation
			span := trace.SpanFromContext(ctx)
			span.SetAttributes(
				attribute.String("auth.username", req.Username),
				attribute.Int("auth.password_length", len(req.Password)),
				attribute.String("auth.client_ip", c.RealIP()),
				attribute.String("auth.user_agent", c.Request().UserAgent()),
				attribute.String("auth.request_method", c.Request().Method),
			)

			var err error
			user, err = ctr.s.GetUser(ctx, models.GetUserParams{
				Username: req.Username,
			})
			if err != nil {
				logger.Warn("Login attempt with invalid username",
					"username", req.Username,
					"error", err.Error())
				span.SetAttributes(
					attribute.Bool("auth.username_found", false),
					attribute.String("auth.username_lookup_error", err.Error()),
				)
				// Send response and return a special error to stop execution
				_ = apierrors.HandleUnauthorizedError(c, "Invalid username or password")
				return fmt.Errorf("authentication_failed: invalid username")
			}

			// Extract email domain safely
			emailDomain := "unknown"
			if emailParts := strings.Split(user.Email.String, "@"); len(emailParts) > 1 {
				emailDomain = emailParts[1]
			}

			span.SetAttributes(
				attribute.Bool("auth.username_found", true),
				attribute.Int64("auth.user_id", int64(user.ID)),
				attribute.Bool("auth.user_has_totp", user.Flags.HasFlag(flags.UserTotpEnabled)),
				attribute.String("auth.user_email_domain", emailDomain),
			)

			if err := user.Password.Validate(req.Password); err != nil {
				logger.Warn("Login attempt with invalid password",
					"username", req.Username,
					"userID", user.ID)
				span.SetAttributes(
					attribute.Bool("auth.password_valid", false),
					attribute.String("auth.password_validation_error", err.Error()),
				)
				// Send response and return a special error to stop execution
				_ = apierrors.HandleUnauthorizedError(c, "Invalid username or password")
				return fmt.Errorf("authentication_failed: invalid password")
			}

			span.SetAttributes(attribute.Bool("auth.password_valid", true))
			return nil
		})
		if err != nil {
			// If credential validation failed, stop here - response already sent
			if strings.HasPrefix(err.Error(), "authentication_failed:") {
				return nil // Return nil to indicate the response was already handled
			}
			return err
		}

		// Check if the user has 2FA enabled and if so, return a state token to the client
		if user.Flags.HasFlag(flags.UserTotpEnabled) {
			return tracing.TraceOperation(ctx, "create_mfa_state", func(ctx context.Context) error {
				state, err := ctr.createStateToken(ctx, user.ID)
				if err != nil {
					logger.Error("Failed to create state token",
						"userID", user.ID,
						"error", err.Error())
					return apierrors.HandleInternalError(c, err, "Failed to create authentication state")
				}

				response := &loginStateResponse{
					StateToken: state,
					ExpiresAt:  ctr.now().UTC().Add(5 * time.Minute),
					Status:     "MFA_REQUIRED",
				}

				return c.JSON(http.StatusOK, response)
			})
		}

		// Trace token generation stage
		var tokens *helper.TokenDetails
		err = tracing.TraceOperation(ctx, "generate_tokens", func(ctx context.Context) error {
			claims := &helper.JwtClaims{
				UserID:   user.ID,
				Username: user.Username,
			}

			adminLevel, err := checks.User.IsAdmin(user.ID)
			if err != nil {
				logger.Error("Failed to check admin level",
					"userID", user.ID,
					"error", err.Error())
				return apierrors.HandleInternalError(c, err, "Failed to check user permissions")
			}
			if adminLevel > 0 {
				claims.Adm = adminLevel
			}

			scopes, err := ctr.getScopes(ctx, user.ID)
			if err != nil {
				logger.Error("Failed to get user scopes",
					"userID", user.ID,
					"error", err.Error())
				return apierrors.HandleInternalError(c, err, "Failed to get user permissions")
			}
			claims.Scope = scopes

			tokens, err = helper.GenerateToken(claims, ctr.now())
			if err != nil {
				logger.Error("Failed to generate tokens",
					"userID", user.ID,
					"error", err.Error())
				return apierrors.HandleInternalError(c, err, "Failed to generate authentication tokens")
			}
			return nil
		})
		if err != nil {
			return err
		}

		// Trace token storage stage
		err = tracing.TraceOperation(ctx, "store_refresh_token", func(ctx context.Context) error {
			err := ctr.storeRefreshToken(ctx, user.ID, tokens)
			if err != nil {
				logger.Error("Failed to store refresh token",
					"userID", user.ID,
					"error", err.Error())
				return apierrors.HandleInternalError(c, err, "Failed to store authentication token")
			}
			return nil
		})
		if err != nil {
			return err
		}

		response := &LoginResponse{
			AccessToken:  tokens.AccessToken,
			RefreshToken: tokens.RefreshToken,
		}

		writeCookie(c, "refresh_token", tokens.RefreshToken, tokens.RtExpires.Time)

		logger.Info("User successfully logged in",
			"userID", user.ID,
			"username", user.Username)

		return c.JSON(http.StatusOK, response)
	})
}

type logoutRequest struct {
	LogoutAll bool `json:"logout_all"`
}

// Logout godoc
// @Summary Logout
// @Description Logs out the user by deleting the refresh token from the database. If `{logout_all: true}` is posted,
// @Description all refresh tokens for the user will be deleted, invalidating all refresh tokens.
// @Tags auth
// @Accept json
// @Produce json
// @Param data body logoutRequest true "Logout request"
// @Success 200 {string} string "Logged out"
// @Failure 401 {object} errors.ErrorResponse "Unauthorized"
// @Security JWTBearerToken
// @Router /logout [post]
func (ctr *AuthenticationController) Logout(c echo.Context) error {
	logger := helper.GetRequestLogger(c)

	claims := helper.GetClaimsFromContext(c)
	req := new(logoutRequest)
	if err := c.Bind(req); err != nil {
		return apierrors.HandleBadRequestError(c, "Invalid request format")
	}

	if err := c.Validate(req); err != nil {
		return apierrors.HandleValidationError(c, err)
	}

	deletedRows, err := ctr.deleteRefreshToken(
		c.Request().Context(),
		claims.UserID,
		claims.RefreshUUID,
		req.LogoutAll,
	)

	deleteCookie(c, "refresh_token")

	if err != nil || deletedRows == 0 {
		logger.Warn("Failed to logout user",
			"userID", claims.UserID,
			"deletedRows", deletedRows,
			"error", err)
		return apierrors.HandleUnauthorizedError(c, "Failed to logout")
	}

	logger.Info("User logged out successfully",
		"userID", claims.UserID,
		"logoutAll", req.LogoutAll)

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Successfully logged out",
	})
}

// RefreshToken godoc
// @Summary Refresh JWT token
// @Description Refreshes the JWT token using the refresh token stored in the client's cookie.
// @Tags auth
// @Accept json
// @Produce json
// @Success 200 {object} LoginResponse
// @Failure 400 {object} errors.ErrorResponse "Bad request"
// @Failure 401 {object} errors.ErrorResponse "Unauthorized"
// @Router /authn/refresh [post]
func (ctr *AuthenticationController) RefreshToken(c echo.Context) error {
	logger := helper.GetRequestLogger(c)

	ctx := c.Request().Context()
	refreshToken, err := readCookie(c, "refresh_token")
	if err != nil {
		logger.Warn("Missing or invalid refresh token in cookie",
			"error", err.Error())
		return apierrors.HandleUnauthorizedError(c, "Invalid or missing refresh token")
	}

	claims, err := helper.GetClaimsFromRefreshToken(refreshToken)

	if err == nil {
		refreshUUID := claims["refresh_uuid"].(string)
		userID := int32(claims["user_id"].(float64))

		user, terr := ctr.s.GetUser(ctx, models.GetUserParams{
			ID: userID,
		})
		if terr != nil {
			logger.Error("User not found during token refresh",
				"userID", userID,
				"error", terr.Error())
			return apierrors.HandleUnauthorizedError(c, "Invalid user")
		}

		deletedRows, err := ctr.deleteRefreshToken(ctx, userID, refreshUUID, false)
		if err != nil || deletedRows == 0 {
			logger.Error("Failed to delete refresh token",
				"userID", userID,
				"refreshUUID", refreshUUID,
				"error", err)
			return apierrors.HandleUnauthorizedError(c, "Invalid refresh token")
		}

		// Prepare new tokens
		newClaims := &helper.JwtClaims{}
		if err := ctr.setClaims(newClaims, &user); err != nil {
			logger.Error("Failed to set token claims",
				"userID", userID,
				"error", err.Error())
			return apierrors.HandleInternalError(c, err, "Failed to create token claims")
		}

		newTokens, err := helper.GenerateToken(newClaims, ctr.now())
		if err != nil {
			logger.Error("Failed to generate new tokens",
				"userID", userID,
				"error", err.Error())
			return apierrors.HandleInternalError(c, err, "Failed to generate new tokens")
		}

		if err := ctr.storeRefreshToken(ctx, user.ID, newTokens); err != nil {
			logger.Error("Failed to store new refresh token",
				"userID", user.ID,
				"error", err.Error())
			return apierrors.HandleInternalError(c, err, "Failed to store new token")
		}

		writeCookie(c, "refresh_token", newTokens.RefreshToken, newTokens.RtExpires.Time)

		response := &LoginResponse{
			AccessToken:  newTokens.AccessToken,
			RefreshToken: newTokens.RefreshToken,
		}

		logger.Info("Token refreshed successfully",
			"userID", user.ID)

		return c.JSON(http.StatusOK, response)
	}

	logger.Warn("Failed to parse refresh token",
		"error", err.Error())
	return apierrors.HandleUnauthorizedError(c, "Refresh token expired")
}

// factorRequest defines the request payload for MFA factor verification
type factorRequest struct {
	StateToken string `json:"state_token" validate:"required"    extensions:"x-order=0"` // State token from login response
	OTP        string `json:"otp"         validate:"required,min=6,max=12" extensions:"x-order=1"` // 6-digit TOTP code or backup code (format: abcde-12345)
}

// validateOTPInput validates the OTP input for both TOTP and backup code formats
func validateOTPInput(input string) error {
	// Trim whitespace
	input = strings.TrimSpace(input)

	// Check if it's a TOTP code (6 digits)
	if matched, _ := regexp.MatchString(`^[0-9]{6}$`, input); matched {
		return nil
	}

	// Check if it's a backup code format (with or without normalization)
	normalized := backupcodes.NormalizeBackupCode(input)
	if err := backupcodes.ValidateBackupCodeFormat(normalized); err == nil {
		return nil
	}

	return errors.New("OTP must be either 6 digits (TOTP) or backup code format (abcde-12345)")
}

// isTOTPCode checks if the input is a TOTP code (6 digits)
func isTOTPCode(input string) bool {
	matched, _ := regexp.MatchString(`^[0-9]{6}$`, input)
	return matched
}

// normalizeAndValidateBackupCode normalizes and validates a backup code input
func normalizeAndValidateBackupCode(input string) (string, error) {
	normalized := backupcodes.NormalizeBackupCode(input)
	if err := backupcodes.ValidateBackupCodeFormat(normalized); err != nil {
		return "", err
	}
	return normalized, nil
}

// validateBackupCodeWithConstantTime validates a backup code against stored codes using constant-time comparison
func validateBackupCodeWithConstantTime(inputCode string, storedCodes []backupcodes.BackupCode) bool {
	// Normalize input while preserving case sensitivity
	normalizedInput := strings.ReplaceAll(strings.ReplaceAll(inputCode, " ", ""), "-", "")

	// Use constant-time comparison for each stored code
	for _, storedCode := range storedCodes {
		// Normalize stored code (remove hyphen but preserve case)
		normalizedStored := strings.ReplaceAll(storedCode.Code, "-", "")

		// Compare using constant-time comparison to prevent timing attacks
		if subtle.ConstantTimeCompare([]byte(normalizedInput), []byte(normalizedStored)) == 1 {
			return true
		}
	}

	return false
}

// VerifyFactor is used to verify the user factor (OTP)
// @Summary Verify MFA factor
// @Description Verifies the user's MFA factor and returns a JWT token if successful.
// @Description Accepts either a 6-digit TOTP code or a backup code (format: abcde-12345).
// @Description The state token, returned from `/login` if the user has TOTP enabled, is used in conjunction with
// @Description the OTP (TOTP code or backup code) to retrieve the actual JWT token.
// @Description When a backup code is used, it is automatically consumed and cannot be reused.
// @Tags auth
// @Accept json
// @Produce json
// @Param data body factorRequest true "State token and OTP"
// @Success 200 {object} LoginResponse
// @Failure 400 {object} errors.ErrorResponse "Bad request"
// @Failure 401 {object} errors.ErrorResponse "Unauthorized"
// @Router /authn/factor_verify [post]
func (ctr *AuthenticationController) VerifyFactor(c echo.Context) error {
	logger := helper.GetRequestLogger(c)

	ctx := c.Request().Context()
	req := new(factorRequest)
	if err := c.Bind(req); err != nil {
		return apierrors.HandleBadRequestError(c, "Invalid request format")
	}

	if err := c.Validate(req); err != nil {
		return apierrors.HandleValidationError(c, err)
	}

	// Additional OTP format validation (TOTP or backup code)
	if err := validateOTPInput(req.OTP); err != nil {
		return apierrors.HandleValidationError(c, err)
	}

	// Verify the state token
	userID, err := ctr.validateStateToken(ctx, req.StateToken)
	if err != nil || userID == 0 {
		logger.Warn("Invalid or expired state token provided",
			"stateToken", req.StateToken,
			"error", err)
		return apierrors.HandleBadRequestError(c, "Invalid or expired state token")
	}

	user, err := ctr.s.GetUser(ctx, models.GetUserParams{
		ID: userID,
	})
	if err != nil {
		logger.Error("User not found during factor verification",
			"userID", userID,
			"error", err.Error())
		return apierrors.HandleNotFoundError(c, "User")
	}

	if user.Flags.HasFlag(flags.UserTotpEnabled) && user.TotpKey.String != "" {
		isAuthenticated := false
		var usedBackupCode string

		// Check if input is a TOTP code (6 digits)
		if isTOTPCode(req.OTP) {
			// Validate TOTP code
			t := totp.New(user.TotpKey.String, 6, 30, config.ServiceTotpSkew.GetUint8())
			isAuthenticated = t.Validate(req.OTP)

			if isAuthenticated {
				logger.Info("TOTP authentication successful",
					"userID", user.ID,
					"username", user.Username)
			}
		} else {
			// Try backup code authentication
			normalizedCode, err := normalizeAndValidateBackupCode(req.OTP)
			if err != nil {
				logger.Warn("Invalid backup code format provided during factor verification",
					"userID", userID,
					"error", err.Error())
				return apierrors.HandleUnauthorizedError(c, "Invalid OTP")
			}

			// Initialize backup code generator
			generator := backupcodes.NewBackupCodeGenerator(ctr.s.(models.ServiceInterface))

			// Get user's backup codes
			backupCodes, err := generator.GetBackupCodes(ctx, user.ID)
			if err != nil {
				logger.Error("Failed to retrieve backup codes during authentication",
					"userID", user.ID,
					"error", err.Error())
				return apierrors.HandleInternalError(c, err, "Failed to verify backup code")
			}

			// Validate backup code using constant-time comparison
			if len(backupCodes) > 0 && validateBackupCodeWithConstantTime(normalizedCode, backupCodes) {
				isAuthenticated = true
				usedBackupCode = normalizedCode

				logger.Info("Backup code authentication successful",
					"userID", user.ID,
					"username", user.Username,
					"codesRemaining", len(backupCodes)-1)
			}
		}

		if isAuthenticated {
			// If backup code was used, consume it (delete from stored codes)
			if usedBackupCode != "" {
				generator := backupcodes.NewBackupCodeGenerator(ctr.s.(models.ServiceInterface))
				consumed, err := generator.ConsumeBackupCode(ctx, user.ID, usedBackupCode, fmt.Sprintf("%d", user.ID))
				if err != nil {
					logger.Error("Failed to consume backup code after successful authentication",
						"userID", user.ID,
						"error", err.Error())
					return apierrors.HandleInternalError(c, err, "Failed to update backup codes")
				}

				if !consumed {
					logger.Warn("Backup code was not found during consumption (possible race condition)",
						"userID", user.ID)
					return apierrors.HandleUnauthorizedError(c, "Invalid OTP")
				}
			}

			// Delete the state token now that authentication has been verified
			ctr.deleteStatetoken(ctx, req.StateToken)

			claims := &helper.JwtClaims{}
			if err := ctr.setClaims(claims, &user); err != nil {
				logger.Error("Failed to set claims for verified user",
					"userID", userID,
					"error", err.Error())
				return apierrors.HandleInternalError(c, err, "Failed to create user claims")
			}

			tokens, err := helper.GenerateToken(claims, ctr.now())
			if err != nil {
				logger.Error("Failed to generate tokens after factor verification",
					"userID", userID,
					"error", err.Error())
				return apierrors.HandleInternalError(c, err, "Failed to generate authentication tokens")
			}

			err = ctr.storeRefreshToken(ctx, user.ID, tokens)
			if err != nil {
				logger.Error("Failed to store refresh token after factor verification",
					"userID", user.ID,
					"error", err.Error())
				return apierrors.HandleInternalError(c, err, "Failed to store authentication token")
			}

			response := &LoginResponse{
				AccessToken:  tokens.AccessToken,
				RefreshToken: tokens.RefreshToken,
			}

			writeCookie(c, "refresh_token", tokens.RefreshToken, tokens.RtExpires.Time)

			logger.Info("MFA factor verified successfully",
				"userID", user.ID,
				"username", user.Username)

			return c.JSON(http.StatusOK, response)
		}
	}

	logger.Warn("Invalid OTP provided during factor verification",
		"userID", userID)
	return apierrors.HandleUnauthorizedError(c, "Invalid OTP")
}

func (ctr *AuthenticationController) storeRefreshToken(
	ctx context.Context,
	userID int32,
	t *helper.TokenDetails,
) error {
	rt := time.Unix(t.RtExpires.Unix(), 0)
	key := fmt.Sprintf("user:%d:rt:%s", userID, t.RefreshUUID)
	err := ctr.rdb.Set(ctx, key, strconv.Itoa(int(userID)), rt.Sub(ctr.now())).Err()
	if err != nil {
		return err
	}
	return nil
}

func (ctr *AuthenticationController) deleteRefreshToken(
	ctx context.Context,
	userID int32,
	tokenUUID string,
	all bool,
) (int64, error) {
	var key string
	if all {
		key = fmt.Sprintf("user:%d:rt:*", userID)
	} else {
		key = fmt.Sprintf("user:%d:rt:%s", userID, tokenUUID)
	}

	rowsDeleted, err := ctr.rdb.Del(ctx, key).Result()
	if err != nil {
		return 0, err
	}
	return rowsDeleted, nil
}

func (ctr *AuthenticationController) createStateToken(ctx context.Context, userID int32) (string, error) {
	// Create a random state token
	state := random.String(32)
	key := fmt.Sprintf("user:mfa:state:%s", state)
	ctr.rdb.Set(ctx, key, strconv.Itoa(int(userID)), time.Minute*3)
	return state, nil
}

func (ctr *AuthenticationController) validateStateToken(ctx context.Context, state string) (int32, error) {
	key := fmt.Sprintf("user:mfa:state:%s", state)
	userID, err := ctr.rdb.Get(ctx, key).Result()
	if err != nil {
		return 0, err
	}
	userIDInt, err := helper.SafeAtoi32(userID)
	if err != nil {
		return 0, err
	}
	return userIDInt, nil
}

func (ctr *AuthenticationController) deleteStatetoken(ctx context.Context, state string) {
	key := fmt.Sprintf("user:mfa:state:%s", state)
	ctr.rdb.Del(ctx, key)
}

// getScopes returns the roles as a string of the user
func (ctr *AuthenticationController) getScopes(ctx context.Context, userID int32) (string, error) {
	roles, err := ctr.s.ListUserRoles(ctx, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil
		}
		return "", err
	}
	roleNames := make([]string, len(roles))
	for i, role := range roles {
		roleNames[i] = role.Name
	}
	return strings.Join(roleNames, " "), nil
}

// writeCookie writes a cookie to the client
func writeCookie(c echo.Context, name, value string, expires time.Time) {
	cookie := new(http.Cookie)
	cookie.Name = name
	cookie.Value = value
	cookie.Expires = expires
	cookie.Path = "/"
	if config.ServiceCookieSameSiteNone.GetBool() {
		cookie.SameSite = http.SameSiteNoneMode
	}
	cookie.Secure = !config.ServiceDevMode.GetBool()
	cookie.Partitioned = true
	cookie.HttpOnly = !config.ServiceDevMode.GetBool()
	c.SetCookie(cookie)
}

// readCookie reads a cookie from the client
func readCookie(c echo.Context, name string) (string, error) {
	cookie, err := c.Cookie(name)
	if err != nil {
		return "", err
	}
	return cookie.Value, nil
}

// deleteCookie deletes a cookie from the client
func deleteCookie(c echo.Context, name string) {
	cookie := new(http.Cookie)
	cookie.Name = name
	cookie.MaxAge = -1
	cookie.Path = "/"
	c.SetCookie(cookie)
}

func (ctr *AuthenticationController) setClaims(claims *helper.JwtClaims, user *models.GetUserRow) error {
	claims.UserID = user.ID
	claims.Username = user.Username

	adminLevel, err := checks.User.IsAdmin(user.ID)
	if err != nil {
		return err
	}
	if adminLevel > 0 {
		claims.Adm = adminLevel
	}

	scopes, err := ctr.getScopes(context.Background(), user.ID)
	if err != nil {
		return err
	}
	claims.Scope = scopes
	return nil
}

// passwordResetRequest is the struct holding the data for the password reset request
type passwordResetRequest struct {
	Email string `json:"email" validate:"required,email" extensions:"x-order=0"`
}

// passwordResetResponse is the response sent to a client upon password reset request
type passwordResetResponse struct {
	Message string `json:"message" extensions:"x-order=0"`
}

// RequestPasswordReset godoc
// @Summary Request Password Reset
// @Description Initiates a password reset process by sending a reset link to the user's email address.
// @Description This endpoint always returns 200 OK regardless of whether the email exists to prevent email enumeration attacks.
// @Description If the email exists in the system, a password reset email will be sent.
// @Tags auth
// @Accept json
// @Produce json
// @Param data body passwordResetRequest true "Password reset request"
// @Success 200 {object} passwordResetResponse
// @Failure 400 {object} errors.ErrorResponse "Bad request"
// @Failure 500 {object} errors.ErrorResponse "Internal server error"
// @Router /forgot-password [post]
func (ctr *AuthenticationController) RequestPasswordReset(c echo.Context) error {
	logger := helper.GetRequestLogger(c)

	ctx := c.Request().Context()
	req := new(passwordResetRequest)

	if err := c.Bind(req); err != nil {
		logger.Error("Failed to bind password reset request",
			"error", err.Error())
		return apierrors.HandleBadRequestError(c, "Invalid request format")
	}

	if err := c.Validate(req); err != nil {
		return apierrors.HandleValidationError(c, err)
	}

	// Always return success to prevent email enumeration attacks
	response := &passwordResetResponse{
		Message: "If the email address exists in our system, you will receive a password reset link shortly.",
	}

	// Try to find the user by email
	user, err := ctr.s.GetUser(ctx, models.GetUserParams{
		Email: req.Email,
	})
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			// Log the error but don't reveal it to the client
			logger.Error("Error looking up user by email",
				"email", req.Email,
				"error", err.Error())
		}
		// Return success even if user not found to prevent enumeration
		return c.JSON(http.StatusOK, response)
	}

	// Generate password reset token
	resetToken, err := ctr.tokenManager.CreateToken(ctx, user.ID)
	if err != nil {
		logger.Error("Failed to create password reset token",
			"userID", user.ID,
			"email", req.Email,
			"error", err.Error())
		// Still return success to prevent revealing errors
		return c.JSON(http.StatusOK, response)
	}

	// Send email only if mail service is enabled
	if config.ServiceMailEnabled.GetBool() {
		// Calculate expiration time for display
		tokenLifetime := ctr.tokenManager.GetTokenTimeRemaining(resetToken)
		expiresIn := formatDuration(tokenLifetime)

		// Generate the reset URL with the token
		baseURL := config.ServiceBaseURL.GetString()
		resetURL := fmt.Sprintf("%s/reset-password?token=%s", baseURL, resetToken.Token)

		// Define template data for the password reset email
		templateData := map[string]any{
			"Username":  user.Username,
			"ResetURL":  resetURL,
			"ExpiresIn": expiresIn,
			"Year":      time.Now().Year(),
		}

		m := mail.NewMail(req.Email, "Reset Your UnderNET CService Password", "password_reset", templateData)
		if err := m.Send(); err != nil {
			logger.Error("Failed to send password reset email",
				"email", req.Email,
				"userID", user.ID,
				"error", err.Error())
			// Still return success to prevent revealing errors
		} else {
			logger.Info("Password reset email sent successfully",
				"email", req.Email,
				"userID", user.ID)
		}
	} else {
		logger.Info("Mail service disabled, skipping password reset email")
	}

	return c.JSON(http.StatusOK, response)
}

// formatDuration formats a duration into a human-readable string
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%d seconds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%d hours", int(d.Hours()))
	}
	return fmt.Sprintf("%d days", int(d.Hours()/24))
}

// resetPasswordRequest is the struct holding the data for the password reset
type resetPasswordRequest struct {
	Token           string `json:"token"            validate:"required"                     extensions:"x-order=0"`
	NewPassword     string `json:"new_password"     validate:"required,min=10,max=72"       extensions:"x-order=1"`
	ConfirmPassword string `json:"confirm_password" validate:"required,eqfield=NewPassword" extensions:"x-order=2"`
}

// resetPasswordResponse is the response sent to a client upon successful password reset
type resetPasswordResponse struct {
	Message string `json:"message" extensions:"x-order=0"`
}

// ResetPassword godoc
// @Summary Reset Password
// @Description Resets a user's password using a valid password reset token received via email.
// @Description The token must be valid, not expired, and not previously used.
// @Tags auth
// @Accept json
// @Produce json
// @Param data body resetPasswordRequest true "Password reset data"
// @Success 200 {object} resetPasswordResponse
// @Failure 400 {object} errors.ErrorResponse "Bad request"
// @Failure 401 {object} errors.ErrorResponse "Invalid or expired token"
// @Failure 500 {object} errors.ErrorResponse "Internal server error"
// @Router /reset-password [post]
func (ctr *AuthenticationController) ResetPassword(c echo.Context) error {
	logger := helper.GetRequestLogger(c)

	ctx := c.Request().Context()
	req := new(resetPasswordRequest)

	if err := c.Bind(req); err != nil {
		logger.Error("Failed to bind password reset request",
			"error", err.Error())
		return apierrors.HandleBadRequestError(c, "Invalid request format")
	}

	if err := c.Validate(req); err != nil {
		return apierrors.HandleValidationError(c, err)
	}

	// Validate the token and get the associated user
	tokenData, err := ctr.tokenManager.ValidateToken(ctx, req.Token)
	if err != nil {
		logger.Warn("Invalid password reset token provided",
			"token", req.Token,
			"error", err.Error())
		return apierrors.HandleUnauthorizedError(c, "Invalid or expired password reset token")
	}

	// Get user information
	user, err := ctr.s.GetUser(ctx, models.GetUserParams{
		ID: tokenData.UserID.Int32,
	})
	if err != nil {
		logger.Error("Failed to get user for password reset",
			"userID", tokenData.UserID.Int32,
			"error", err.Error())
		return apierrors.HandleInternalError(c, err, "Failed to process password reset")
	}

	// Hash the new password
	err = user.Password.Set(req.NewPassword)
	if err != nil {
		logger.Error("Failed to hash new password",
			"userID", user.ID,
			"error", err.Error())
		return apierrors.HandleInternalError(c, err, "Failed to process password reset")
	}

	// Update the user's password
	err = ctr.s.UpdateUserPassword(ctx, models.UpdateUserPasswordParams{
		ID:       user.ID,
		Password: user.Password,
	})
	if err != nil {
		logger.Error("Failed to update password in database",
			"userID", user.ID,
			"error", err.Error())
		return apierrors.HandleDatabaseError(c, err)
	}

	// Mark the token as used
	err = ctr.tokenManager.UseToken(ctx, req.Token)
	if err != nil {
		logger.Error("Failed to mark password reset token as used",
			"userID", user.ID,
			"token", req.Token,
			"error", err.Error())
		// Don't return error here as password was already updated successfully
	}

	// Invalidate any other pending reset tokens for this user
	err = ctr.tokenManager.InvalidateUserTokens(ctx, tokenData.UserID.Int32)
	if err != nil {
		logger.Error("Failed to invalidate other password reset tokens",
			"userID", tokenData.UserID.Int32,
			"error", err.Error())
		// Don't return error here as password was already updated successfully
	}

	logger.Info("Password reset completed successfully",
		"userID", user.ID,
		"username", user.Username)

	response := resetPasswordResponse{
		Message: "Your password has been successfully reset. You can now log in with your new password.",
	}

	return c.JSON(http.StatusOK, response)
}
