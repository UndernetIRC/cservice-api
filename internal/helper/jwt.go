// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package helper

import (
	"github.com/golang-jwt/jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/twinj/uuid"
	"github.com/undernetirc/cservice-api/internal/config"
	"time"
)

type JwtClaims struct {
	UserId        int32  `json:"user_id"`
	Username      string `json:"username"`
	Authenticated bool   `json:"authenticated"`
	RefreshUUID   string `json:"refresh_uuid"` // If 2FA is enabled, this will be false until the user has authenticated with TOTP
	jwt.RegisteredClaims
}

type TokenDetails struct {
	AccessToken  string
	RefreshToken string
	RefreshUUID  string
	AtExpires    *jwt.NumericDate
	RtExpires    *jwt.NumericDate
}

func GenerateToken(claims *JwtClaims) (*TokenDetails, error) {
	td := &TokenDetails{}
	td.AtExpires = jwt.NewNumericDate(time.Now().Add(time.Minute * 5))    // 5 minutes
	td.RtExpires = jwt.NewNumericDate(time.Now().Add(time.Hour * 24 * 7)) // 7 days
	td.RefreshUUID = uuid.NewV4().String()

	claims.RefreshUUID = td.RefreshUUID
	claims.RegisteredClaims = jwt.RegisteredClaims{
		ExpiresAt: td.AtExpires,
	}

	accessToken := jwt.NewWithClaims(jwt.GetSigningMethod(config.Conf.JWT.SigningMethod), claims)
	accessToken.Header["kid"] = "at"
	at, err := accessToken.SignedString(config.Conf.GetJWTSigningKey())
	if err != nil {
		return nil, err
	}
	td.AccessToken = at

	if claims.Authenticated { // Only generate refresh token if the user has fully authenticated
		refreshToken := jwt.New(jwt.GetSigningMethod(config.Conf.JWT.SigningMethod))
		refreshToken.Header["kid"] = "rt"
		rtClaims := refreshToken.Claims.(jwt.MapClaims)
		rtClaims["refresh_uuid"] = td.RefreshUUID
		rtClaims["user_id"] = claims.UserId
		rtClaims["sub"] = 1
		rtClaims["exp"] = td.RtExpires
		rt, err := refreshToken.SignedString(config.Conf.GetJWTRefreshSigningKey())
		if err != nil {
			return nil, err
		}
		td.RefreshToken = rt
	}

	return td, nil
}

func GetClaimsFromContext(c echo.Context) *JwtClaims {
	token := c.Get("user").(*jwt.Token)
	claims := token.Claims.(*JwtClaims)
	return claims
}
