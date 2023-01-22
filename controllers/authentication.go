// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

// Package controllers provides the controllers for the API
package controllers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/go-redis/redis/v9"
	"github.com/golang-jwt/jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/gommon/random"
	"github.com/undernetirc/cservice-api/internal/auth"
	"github.com/undernetirc/cservice-api/internal/auth/oath/totp"
	"github.com/undernetirc/cservice-api/internal/config"
	"github.com/undernetirc/cservice-api/internal/helper"
	"github.com/undernetirc/cservice-api/models"
)

type AuthenticationController struct {
	s   models.Querier
	rdb *redis.Client
}

func NewAuthenticationController(s models.Querier, rdb *redis.Client) *AuthenticationController {
	return &AuthenticationController{s: s, rdb: rdb}
}

// loginRequest is the struct holding the data for the login request
type loginRequest struct {
	Username string `json:"username" validate:"required,min=2,max=12" extensions:"x-order=0"`
	Password string `json:"password" validate:"required" extensions:"x-order=1"`
}

// loginResponse is the response sent to a client upon successful FULL authentication
type loginResponse struct {
	AccessToken  string `json:"access_token" extensions:"x-order=0"`
	RefreshToken string `json:"refresh_token,omitempty" extensions:"x-order=1"`
}

// loginStateResponse is the response sent to the client when an additional authentication factor is required
type loginStateResponse struct {
	StateToken string    `json:"state_token" extensions:"x-order=0"`
	ExpiresAt  time.Time `json:"expires_at" extensions:"x-order=1"`
	Status     string    `json:"status" extensions:"x-order=2"`
}

// customError allows us to return custom errors to the client
type customError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Login example
// @Summary Authenticate user to retrieve JWT token
// @Tags accounts
// @Accept json
// @Produce json
// @Param data body loginRequest true "Login request"
// @Success 200 {object} loginResponse
// @Failure 401 "Invalid username or password"
// @Router /authn [post]
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

	if !auth.ValidatePassword(user.Password, req.Password) {
		return c.JSONPretty(http.StatusUnauthorized, customError{
			http.StatusUnauthorized,
			"Invalid username or password",
		}, " ")
	}

	// Check if the user has 2FA enabled and if so, return a state token to the client
	if *user.TotpKey != "" {
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
			ExpiresAt:  time.Now().UTC().Add(5 * time.Minute),
			Status:     "MFA_REQUIRED",
		})
	}

	claims := &helper.JwtClaims{
		UserId:   user.ID,
		Username: user.UserName,
	}

	tokens, err := helper.GenerateToken(claims)
	if err != nil {
		return c.JSONPretty(http.StatusUnauthorized, customError{http.StatusUnauthorized, err.Error()}, " ")
	}

	err = ctr.storeRefreshToken(c.Request().Context(), user.ID, tokens)
	if err != nil {
		return c.JSON(http.StatusUnprocessableEntity, err.Error())
	}

	response := &loginResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}

	return c.JSONPretty(http.StatusOK, response, " ")
}

type logoutRequest struct {
	LogoutAll bool `json:"logout_all"`
}

// Logout godoc
// @Summary Logout user
// @Tags accounts
// @Accept json
// @Produce json
// @Param data body logoutRequest true "Logout request"
// @Success 200 {string} string "Logged out"
// @Failure 400 {object} customError "Bad request"
// @Failure 401 {object} customError "Unauthorized"
// @Router /authn/logout [post]
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

	deletedRows, err := ctr.deleteRefreshToken(c.Request().Context(), claims.UserId, claims.RefreshUUID, req.LogoutAll)
	if err != nil || deletedRows == 0 {
		return c.JSON(http.StatusUnauthorized, "unauthorized")
	}

	return c.JSON(http.StatusOK, "Successfully logged out")
}

type refreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" valid:"required"`
}

// RefreshToken godoc
// @Summary Request new session tokens using a Refresh JWT token
// @Tags accounts
// @Accept json
// @Produce json
// @Param data body refreshTokenRequest true "Refresh token"
// @Success 200 {object} loginResponse
// @Failure 400 {object} customError "Bad request"
// @Failure 401 {object} customError "Unauthorized"
// @Router /authn/refresh [post]
func (ctr *AuthenticationController) RefreshToken(c echo.Context) error {
	req := new(refreshTokenRequest)
	if err := c.Bind(req); err != nil {
		return c.JSON(http.StatusBadRequest, err)
	}

	if err := c.Validate(req); err != nil {
		c.Logger().Error(err)
		return c.JSON(http.StatusBadRequest, customError{
			Code:    http.StatusBadRequest,
			Message: err.Error(),
		})
	}

	// Verify the refresh token
	var token *jwt.Token
	var err error

	if config.Conf.JWT.SigningMethod == "RS256" {
		token, err = jwt.Parse(req.RefreshToken, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			f, ferr := os.ReadFile(config.Conf.JWT.RefreshPublicKey)
			if ferr != nil {
				return nil, ferr
			}
			pubKey, ferr := jwt.ParseRSAPublicKeyFromPEM(f)
			if ferr != nil {
				return nil, errors.New("an error occurred parsing the public key")
			}

			return pubKey, nil
		})
	} else {
		token, err = jwt.Parse(req.RefreshToken, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(config.Conf.JWT.RefreshSigningKey), nil
		})
	}

	if err != nil {
		c.Logger().Error(err)
		return c.JSON(http.StatusUnauthorized, "refresh token expired")
	}

	claims, ok := token.Claims.(jwt.MapClaims)

	if ok && token.Valid {
		refreshUUID := claims["refresh_uuid"].(string)
		userId := int32(claims["user_id"].(float64))

		user, terr := ctr.s.GetUserByID(c.Request().Context(), userId)
		if terr != nil {
			return c.JSON(http.StatusUnauthorized, "unauthorized")
		}

		deletedRows, err := ctr.deleteRefreshToken(c.Request().Context(), userId, refreshUUID, false)
		if err != nil || deletedRows == 0 {
			return c.JSON(http.StatusUnauthorized, "unauthorized")
		}

		// Prepare new tokens
		newClaims := &helper.JwtClaims{
			UserId:   user.ID,
			Username: user.UserName,
		}
		newTokens, err := helper.GenerateToken(newClaims)
		if err != nil {
			return c.JSON(http.StatusForbidden, err.Error())
		}

		if err := ctr.storeRefreshToken(c.Request().Context(), user.ID, newTokens); err != nil {
			return c.JSON(http.StatusUnauthorized, err.Error())
		}

		return c.JSON(http.StatusOK, &loginResponse{
			AccessToken:  newTokens.AccessToken,
			RefreshToken: newTokens.RefreshToken,
		})
	}
	return c.JSON(http.StatusUnauthorized, "refresh token expired")
}

type factorRequest struct {
	StateToken string `json:"state_token" valid:"required"`
	OTP        string `json:"otp" validate:"required,numeric,len=6"`
}

func (ctr *AuthenticationController) VerifyFactor(c echo.Context) error {
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
	userId, err := ctr.validateStateToken(c.Request().Context(), req.StateToken)
	if err != nil || userId == 0 {
		return c.JSON(http.StatusUnauthorized, &customError{
			Code:    http.StatusUnauthorized,
			Message: "Invalid or expired state token",
		})
	}

	user, err := ctr.s.GetUserByID(c.Request().Context(), userId)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, customError{
			Code:    http.StatusUnauthorized,
			Message: "User not found",
		})
	}

	if *user.TotpKey != "" {
		t := totp.New(*user.TotpKey, 6, 30)

		if t.Validate(req.OTP) {
			claims := &helper.JwtClaims{
				UserId:   user.ID,
				Username: user.UserName,
			}
			tokens, err := helper.GenerateToken(claims)
			if err != nil {
				return c.JSONPretty(http.StatusInternalServerError, customError{http.StatusInternalServerError, err.Error()}, " ")
			}
			response := &loginResponse{
				AccessToken:  tokens.AccessToken,
				RefreshToken: tokens.RefreshToken,
			}
			return c.JSON(http.StatusOK, response)
		}
	}
	return c.JSON(http.StatusUnauthorized, customError{http.StatusUnauthorized, "invalid OTP"})
}

func (ctr *AuthenticationController) storeRefreshToken(ctx context.Context, userId int32, t *helper.TokenDetails) error {
	if !config.Conf.Redis.EnableMultiLogout {
		return nil
	}
	fmt.Print("Got here")
	rt := time.Unix(t.RtExpires.Unix(), 0)
	now := time.Now()
	key := fmt.Sprintf("user:%d:rt:%s", userId, t.RefreshUUID)
	err := ctr.rdb.Set(ctx, key, strconv.Itoa(int(userId)), rt.Sub(now)).Err()
	if err != nil {
		return err
	}
	return nil
}

func (ctr *AuthenticationController) deleteRefreshToken(ctx context.Context, userId int32, tokenUUID string, all bool) (int64, error) {
	if !config.Conf.Redis.EnableMultiLogout {
		return 1, nil
	}

	var key string
	if all {
		key = fmt.Sprintf("user:%d:rt:*", userId)
	} else {
		key = fmt.Sprintf("user:%d:rt:%s", userId, tokenUUID)
	}

	rowsDeleted, err := ctr.rdb.Del(ctx, key).Result()
	if err != nil {
		return 0, err
	}
	return rowsDeleted, nil
}

func (ctr *AuthenticationController) createStateToken(ctx context.Context, userId int32) (string, error) {
	// Create a random state token
	state := random.String(32)
	key := fmt.Sprintf("user:mfa:state:%s", state)
	ctr.rdb.Set(ctx, key, strconv.Itoa(int(userId)), time.Minute*5)
	return state, nil
}

func (ctr *AuthenticationController) validateStateToken(ctx context.Context, state string) (int32, error) {
	key := fmt.Sprintf("user:mfa:state:%s", state)
	userId, err := ctr.rdb.Get(ctx, key).Result()
	if err != nil {
		return 0, err
	}
	userIdInt, err := strconv.Atoi(userId)
	if err != nil {
		return 0, err
	}
	ctr.rdb.Del(ctx, key)
	return int32(userIdInt), nil
}
