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

type LoginRequest struct {
	Username string `json:"username" validate:"required,min=2,max=12" extensions:"x-order=0"`
	Password string `json:"password" validate:"required" extensions:"x-order=1"`
	OTP      string `json:"otp" validate:"omitempty,numeric,len=6" extensions:"x-order=2"`
}

type LoginResponse struct {
	AccessToken       string `json:"access_token" extensions:"x-order=0"`
	RefreshToken      string `json:"refresh_token,omitempty" extensions:"x-order=1"`
	TwoFactorRequired bool   `json:"2fa_required,omitempty" extensions:"x-order=3"`
}

type customError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Login godoc
// @Summary Authenticate user to retrieve JWT token
// @Tags accounts
// @Accept json
// @Produce json
// @Param data body LoginRequest true "Login request"
// @Success 200 {object} LoginResponse
// @Failure 401 "Invalid username or password"
// @Router /login [post]
func (ctr *AuthenticationController) Login(c echo.Context) error {
	req := new(LoginRequest)
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

	claims := &helper.JwtClaims{
		UserId:        user.ID,
		Username:      user.UserName,
		Authenticated: !(*user.TotpKey != ""),
	}

	if *user.TotpKey != "" && req.OTP != "" {
		t := totp.New(*user.TotpKey, 6, 30)

		if !t.Validate(req.OTP) {
			return c.JSONPretty(http.StatusUnauthorized, customError{http.StatusUnauthorized, "invalid OTP"}, " ")
		}

		claims.Authenticated = true
	}

	tokens, err := helper.GenerateToken(claims)
	if err != nil {
		return c.JSONPretty(http.StatusUnauthorized, customError{http.StatusUnauthorized, err.Error()}, " ")
	}

	err = ctr.storeRefreshToken(c.Request().Context(), user.ID, tokens)
	if err != nil {
		return c.JSON(http.StatusUnprocessableEntity, err.Error())
	}

	response := &LoginResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}

	if !claims.Authenticated {
		response.TwoFactorRequired = true
	}

	return c.JSONPretty(http.StatusOK, response, " ")
}

type LogoutRequest struct {
	LogoutAll bool `json:"logout_all"`
}

func (ctr *AuthenticationController) Logout(c echo.Context) error {
	claims := helper.GetClaimsFromContext(c)
	req := new(LogoutRequest)
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

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" valid:"required"`
}

func (ctr *AuthenticationController) RefreshToken(c echo.Context) error {
	req := new(RefreshTokenRequest)
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
			UserId:        user.ID,
			Username:      user.UserName,
			Authenticated: true,
		}
		newTokens, err := helper.GenerateToken(newClaims)
		if err != nil {
			return c.JSON(http.StatusForbidden, err.Error())
		}

		if err := ctr.storeRefreshToken(c.Request().Context(), user.ID, newTokens); err != nil {
			return c.JSON(http.StatusUnauthorized, err.Error())
		}

		response := &LoginResponse{
			AccessToken:  newTokens.AccessToken,
			RefreshToken: newTokens.RefreshToken,
		}

		return c.JSON(http.StatusOK, response)
	}
	return c.JSON(http.StatusUnauthorized, "refresh token expired")
}

type otpRequest struct {
	OTP string `json:"otp" validate:"required,numeric,len=6"`
}

func (ctr *AuthenticationController) ValidateOTP(c echo.Context) error {
	req := new(otpRequest)
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

	claims := helper.GetClaimsFromContext(c)

	user, err := ctr.s.GetUserByID(c.Request().Context(), claims.UserId)
	if err != nil {
		return c.JSONPretty(http.StatusUnauthorized, customError{
			Code:    http.StatusUnauthorized,
			Message: "Invalid username or password",
		}, " ")
	}

	if *user.TotpKey != "" {
		t := totp.New(*user.TotpKey, 6, 30)

		if t.Validate(req.OTP) {
			claims.Authenticated = true
			tokens, err := helper.GenerateToken(claims)
			if err != nil {
				return c.JSONPretty(http.StatusInternalServerError, customError{http.StatusInternalServerError, err.Error()}, " ")
			}
			response := &LoginResponse{
				AccessToken:  tokens.AccessToken,
				RefreshToken: tokens.RefreshToken,
			}
			return c.JSONPretty(http.StatusOK, response, " ")
		}
	}
	return c.JSONPretty(http.StatusUnauthorized, customError{http.StatusUnauthorized, "invalid OTP or OTP is not enabled"}, " ")
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
