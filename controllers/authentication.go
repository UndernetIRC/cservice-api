// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023-2024 UnderNET

// Package controllers provides the controllers for the API
package controllers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/labstack/echo/v4"
	"github.com/labstack/gommon/random"
	"github.com/redis/go-redis/v9"

	"github.com/undernetirc/cservice-api/db/types/flags"
	"github.com/undernetirc/cservice-api/internal/auth/oath/totp"
	"github.com/undernetirc/cservice-api/internal/auth/reset"
	"github.com/undernetirc/cservice-api/internal/checks"
	"github.com/undernetirc/cservice-api/internal/config"
	"github.com/undernetirc/cservice-api/internal/helper"
	"github.com/undernetirc/cservice-api/internal/mail"
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

// customError allows us to return custom errors to the client
type customError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
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
// @Failure 401 {object} customError "Invalid username or password"
// @Router /login [post]
func (ctr *AuthenticationController) Login(c echo.Context) error {
	req := new(loginRequest)
	if err := c.Bind(req); err != nil {
		c.Logger().Error(err)
		return c.JSON(http.StatusBadRequest, customError{
			Code:    http.StatusBadRequest,
			Message: err.Error(),
		})
	}

	if err := c.Validate(req); err != nil {
		c.Logger().Error(err)
		return c.JSON(http.StatusBadRequest, customError{
			Code:    http.StatusBadRequest,
			Message: err.Error(),
		})
	}

	user, err := ctr.s.GetUserByUsername(c.Request().Context(), req.Username)
	if err != nil {
		c.Logger().Error(err)
		return c.JSONPretty(http.StatusUnauthorized, customError{
			Code:    http.StatusUnauthorized,
			Message: "Invalid username or password",
		}, " ")
	}

	if err := user.Password.Validate(req.Password); err != nil {
		return c.JSON(http.StatusUnauthorized, customError{
			http.StatusUnauthorized,
			"Invalid username or password",
		})
	}

	// Check if the user has 2FA enabled and if so, return a state token to the client
	if user.Flags.HasFlag(flags.UserTotpEnabled) {
		state, err := ctr.createStateToken(c.Request().Context(), user.ID)
		if err != nil {
			c.Logger().Error(err)
			return c.JSON(http.StatusInternalServerError, &customError{
				Code:    http.StatusInternalServerError,
				Message: "Internal server error",
			})
		}

		return c.JSON(http.StatusOK, &loginStateResponse{
			StateToken: state,
			ExpiresAt:  ctr.now().UTC().Add(5 * time.Minute),
			Status:     "MFA_REQUIRED",
		})
	}

	claims := &helper.JwtClaims{
		UserID:   user.ID,
		Username: user.Username,
	}

	adminLevel, err := checks.User.IsAdmin(user.ID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	if adminLevel > 0 {
		claims.Adm = adminLevel
	}

	scopes, err := ctr.getScopes(c.Request().Context(), user.ID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	claims.Scope = scopes

	tokens, err := helper.GenerateToken(claims, ctr.now())
	if err != nil {
		return c.JSONPretty(
			http.StatusUnauthorized,
			customError{http.StatusUnauthorized, err.Error()},
			" ",
		)
	}

	err = ctr.storeRefreshToken(c.Request().Context(), user.ID, tokens)
	if err != nil {
		return c.JSON(http.StatusUnprocessableEntity, err.Error())
	}

	response := &LoginResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}

	writeCookie(c, "refresh_token", tokens.RefreshToken, tokens.RtExpires.Time)

	return c.JSONPretty(http.StatusOK, response, " ")
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
// @Failure 401 {object} customError "Unauthorized"
// @Security JWTBearerToken
// @Router /logout [post]
func (ctr *AuthenticationController) Logout(c echo.Context) error {
	claims := helper.GetClaimsFromContext(c)
	req := new(logoutRequest)
	if err := c.Bind(req); err != nil {
		return c.JSON(http.StatusBadRequest, err.Error())
	}

	if err := c.Validate(req); err != nil {
		c.Logger().Error(err)
		return c.JSON(http.StatusBadRequest, customError{
			Code:    http.StatusBadRequest,
			Message: err.Error(),
		})
	}

	deletedRows, err := ctr.deleteRefreshToken(
		c.Request().Context(),
		claims.UserID,
		claims.RefreshUUID,
		req.LogoutAll,
	)

	deleteCookie(c, "refresh_token")

	if err != nil || deletedRows == 0 {
		return c.JSON(http.StatusUnauthorized, "unauthorized")
	}

	return c.JSON(http.StatusOK, "Successfully logged out")
}

// RefreshToken godoc
// @Summary Refresh JWT token
// @Description Refreshes the JWT token using the refresh token stored in the client's cookie.
// @Tags auth
// @Accept json
// @Produce json
// @Success 200 {object} LoginResponse
// @Failure 400 {object} customError "Bad request"
// @Failure 401 {object} customError "Unauthorized"
// @Router /authn/refresh [post]
func (ctr *AuthenticationController) RefreshToken(c echo.Context) error {
	ctx := c.Request().Context()
	refreshToken, err := readCookie(c, "refresh_token")
	if err != nil {
		c.Logger().Error(err)
		return c.JSON(http.StatusUnauthorized, customError{
			Code:    http.StatusUnauthorized,
			Message: "invalid or missing refresh token",
		})
	}

	claims, err := helper.GetClaimsFromRefreshToken(refreshToken)

	if err == nil {
		refreshUUID := claims["refresh_uuid"].(string)
		userID := int32(claims["user_id"].(float64))

		user, terr := ctr.s.GetUserByID(ctx, userID)
		if terr != nil {
			c.Logger().Error(terr)
			return c.JSON(http.StatusUnauthorized, "unauthorized")
		}

		deletedRows, err := ctr.deleteRefreshToken(ctx, userID, refreshUUID, false)
		if err != nil || deletedRows == 0 {
			c.Logger().Error(err)
			return c.JSON(http.StatusUnauthorized, "unauthorized")
		}

		// Prepare new tokens
		newClaims := &helper.JwtClaims{}
		if err := ctr.setClaims(newClaims, &user); err != nil {
			return c.JSON(http.StatusInternalServerError, err.Error())
		}

		newTokens, err := helper.GenerateToken(newClaims, ctr.now())
		if err != nil {
			return c.JSON(http.StatusForbidden, err.Error())
		}

		if err := ctr.storeRefreshToken(ctx, user.ID, newTokens); err != nil {
			c.Logger().Error(err)
			return c.JSON(http.StatusUnauthorized, err.Error())
		}

		writeCookie(c, "refresh_token", newTokens.RefreshToken, newTokens.RtExpires.Time)

		return c.JSON(http.StatusOK, &LoginResponse{
			AccessToken:  newTokens.AccessToken,
			RefreshToken: newTokens.RefreshToken,
		})
	}

	c.Logger().Error(err)
	return c.JSON(http.StatusUnauthorized, customError{
		Code:    http.StatusUnauthorized,
		Message: "refresh token expired",
	})
}

type factorRequest struct {
	StateToken string `json:"state_token" validate:"required"`
	OTP        string `json:"otp"         validate:"required,numeric,len=6"`
}

// VerifyFactor is used to verify the user factor (OTP)
// @Summary Verify MFA factor
// @Description Verifies the user's MFA factor (OTP) and returns a JWT token if successful.
// @Description The state token, returned from `/login` if the user has TOTP enabled, it is used in conjunction with
// @Description the OTP (one-time password) to retrieve the actual JWT token
// @Tags auth
// @Accept json
// @Produce json
// @Param data body factorRequest true "State token and OTP"
// @Success 200 {object} LoginResponse
// @Failure 400 {object} customError "Bad request"
// @Failure 401 {object} customError "Unauthorized"
// @Router /authn/factor_verify [post]
func (ctr *AuthenticationController) VerifyFactor(c echo.Context) error {
	ctx := c.Request().Context()
	req := new(factorRequest)
	if err := c.Bind(req); err != nil {
		return c.JSON(http.StatusBadRequest, customError{
			Code:    http.StatusBadRequest,
			Message: err.Error(),
		})
	}

	if err := c.Validate(req); err != nil {
		c.Logger().Error(err)
		return c.JSON(http.StatusBadRequest, customError{
			Code:    http.StatusBadRequest,
			Message: err.Error(),
		})
	}

	// Verify the state token
	userID, err := ctr.validateStateToken(ctx, req.StateToken)
	if err != nil || userID == 0 {
		return c.JSON(http.StatusBadRequest, &customError{
			Code:    http.StatusBadRequest,
			Message: "Invalid or expired state token",
		})
	}

	user, err := ctr.s.GetUserByID(ctx, userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, customError{
			Code:    http.StatusUnauthorized,
			Message: "User not found",
		})
	}

	if user.Flags.HasFlag(flags.UserTotpEnabled) && user.TotpKey.String != "" {
		t := totp.New(user.TotpKey.String, 6, 30, config.ServiceTotpSkew.GetUint8())

		if t.Validate(req.OTP) {
			// Delete the state token now that OTP has been verified
			ctr.deleteStatetoken(ctx, req.StateToken)

			claims := &helper.JwtClaims{}
			if err := ctr.setClaims(claims, &user); err != nil {
				return c.JSON(http.StatusInternalServerError, err.Error())
			}

			tokens, err := helper.GenerateToken(claims, ctr.now())
			if err != nil {
				return c.JSONPretty(
					http.StatusInternalServerError,
					customError{http.StatusInternalServerError, err.Error()},
					" ",
				)
			}
			if err := ctr.storeRefreshToken(ctx, user.ID, tokens); err != nil {
				c.Logger().Error(err)
				return c.JSON(http.StatusUnauthorized, err.Error())
			}

			response := &LoginResponse{
				AccessToken:  tokens.AccessToken,
				RefreshToken: tokens.RefreshToken,
			}

			writeCookie(c, "refresh_token", tokens.RefreshToken, tokens.RtExpires.Time)

			return c.JSON(http.StatusOK, response)
		}
	}
	return c.JSON(http.StatusUnauthorized, customError{http.StatusUnauthorized, "invalid OTP"})
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

func (ctr *AuthenticationController) setClaims(claims *helper.JwtClaims, user *models.GetUserByIDRow) error {
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
// @Failure 400 {object} customError "Bad request"
// @Failure 500 {object} customError "Internal server error"
// @Router /auth/password-reset [post]
func (ctr *AuthenticationController) RequestPasswordReset(c echo.Context) error {
	ctx := c.Request().Context()
	req := new(passwordResetRequest)

	if err := c.Bind(req); err != nil {
		c.Logger().Error(err)
		return c.JSON(http.StatusBadRequest, customError{
			Code:    http.StatusBadRequest,
			Message: err.Error(),
		})
	}

	if err := c.Validate(req); err != nil {
		c.Logger().Error(err)
		return c.JSON(http.StatusBadRequest, customError{
			Code:    http.StatusBadRequest,
			Message: err.Error(),
		})
	}

	// Always return success to prevent email enumeration attacks
	response := &passwordResetResponse{
		Message: "If the email address exists in our system, you will receive a password reset link shortly.",
	}

	// Try to find the user by email
	user, err := ctr.s.GetUserByEmail(ctx, req.Email)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			// Log the error but don't reveal it to the client
			c.Logger().Errorf("Error looking up user by email: %v", err)
		}
		// Return success even if user not found to prevent enumeration
		return c.JSON(http.StatusOK, response)
	}

	// Generate password reset token
	resetToken, err := ctr.tokenManager.CreateToken(ctx, user.ID)
	if err != nil {
		c.Logger().Errorf("Failed to create password reset token for user %d: %v", user.ID, err)
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
			c.Logger().Errorf("Failed to send password reset email to %s: %v", req.Email, err)
			// Still return success to prevent revealing errors
		}
	} else {
		c.Logger().Info("Mail service disabled, skipping password reset email")
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
	Token           string `json:"token" validate:"required" extensions:"x-order=0"`
	NewPassword     string `json:"new_password" validate:"required,min=10,max=72" extensions:"x-order=1"`
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
// @Failure 400 {object} customError "Bad request"
// @Failure 401 {object} customError "Invalid or expired token"
// @Failure 500 {object} customError "Internal server error"
// @Router /auth/reset-password [post]
func (ctr *AuthenticationController) ResetPassword(c echo.Context) error {
	ctx := c.Request().Context()
	req := new(resetPasswordRequest)

	if err := c.Bind(req); err != nil {
		c.Logger().Error(err)
		return c.JSON(http.StatusBadRequest, customError{
			Code:    http.StatusBadRequest,
			Message: err.Error(),
		})
	}

	if err := c.Validate(req); err != nil {
		c.Logger().Error(err)
		return c.JSON(http.StatusBadRequest, customError{
			Code:    http.StatusBadRequest,
			Message: err.Error(),
		})
	}

	// Validate the token and get the associated user
	tokenData, err := ctr.tokenManager.ValidateToken(ctx, req.Token)
	if err != nil {
		c.Logger().Errorf("Invalid password reset token: %v", err)
		return c.JSON(http.StatusUnauthorized, customError{
			Code:    http.StatusUnauthorized,
			Message: "Invalid or expired password reset token",
		})
	}

	// Get user information
	user, err := ctr.s.GetUserByID(ctx, tokenData.UserID.Int32)
	if err != nil {
		c.Logger().Errorf("Failed to get user %d for password reset: %v", tokenData.UserID.Int32, err)
		return c.JSON(http.StatusInternalServerError, customError{
			Code:    http.StatusInternalServerError,
			Message: "Failed to process password reset",
		})
	}

	// Hash the new password
	err = user.Password.Set(req.NewPassword)
	if err != nil {
		c.Logger().Errorf("Failed to hash new password for user %d: %v", user.ID, err)
		return c.JSON(http.StatusInternalServerError, customError{
			Code:    http.StatusInternalServerError,
			Message: "Failed to process password reset",
		})
	}

	// Update the user's password
	err = ctr.s.UpdateUserPassword(ctx, models.UpdateUserPasswordParams{
		ID:       user.ID,
		Password: user.Password,
	})
	if err != nil {
		c.Logger().Errorf("Failed to update password for user %d: %v", user.ID, err)
		return c.JSON(http.StatusInternalServerError, customError{
			Code:    http.StatusInternalServerError,
			Message: "Failed to process password reset",
		})
	}

	// Mark the token as used
	err = ctr.tokenManager.UseToken(ctx, req.Token)
	if err != nil {
		c.Logger().Errorf("Failed to mark password reset token as used: %v", err)
		// Don't return error here as password was already updated successfully
	}

	// Invalidate any other pending reset tokens for this user
	err = ctr.tokenManager.InvalidateUserTokens(ctx, tokenData.UserID.Int32)
	if err != nil {
		c.Logger().Errorf("Failed to invalidate other password reset tokens for user %d: %v", tokenData.UserID.Int32, err)
		// Don't return error here as password was already updated successfully
	}

	return c.JSON(http.StatusOK, resetPasswordResponse{
		Message: "Your password has been successfully reset. You can now log in with your new password.",
	})
}
