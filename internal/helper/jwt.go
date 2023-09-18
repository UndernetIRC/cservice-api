// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

// Package helper contains helper functions
package helper

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/twinj/uuid"
	"github.com/undernetirc/cservice-api/internal/config"
)

// JwtClaims defines the default claims for JWT
type JwtClaims struct {
	UserId      int32  `json:"user_id"`
	Username    string `json:"username"`
	RefreshUUID string `json:"refresh_uuid"` // If 2FA is enabled, this will be false until the user has authenticated with TOTPa
	Scope       string `json:"scope"`
	jwt.RegisteredClaims
}

func (c *JwtClaims) HasScope(scope string) bool {
	result := strings.Split(c.Scope, " ")
	for _, v := range result {
		if v == scope {
			return true
		}
	}
	return false
}

// TokenDetails defines the details of the tokens
type TokenDetails struct {
	AccessToken  string
	RefreshToken string
	RefreshUUID  string
	AtExpires    *jwt.NumericDate
	RtExpires    *jwt.NumericDate
}

// GenerateToken generates a JWT token
func GenerateToken(claims *JwtClaims, t time.Time) (*TokenDetails, error) {
	td := &TokenDetails{}
	td.AtExpires = jwt.NewNumericDate(t.Add(time.Minute * 5))    // 5 minutes
	td.RtExpires = jwt.NewNumericDate(t.Add(time.Hour * 24 * 7)) // 7 days
	td.RefreshUUID = uuid.NewV4().String()

	claims.RefreshUUID = td.RefreshUUID
	claims.RegisteredClaims = jwt.RegisteredClaims{
		ExpiresAt: td.AtExpires,
	}

	accessToken := jwt.NewWithClaims(jwt.GetSigningMethod(config.ServiceJWTSigningMethod.GetString()), claims)
	accessToken.Header["kid"] = "at"
	at, err := accessToken.SignedString(GetJWTSigningKey())
	if err != nil {
		return nil, err
	}
	td.AccessToken = at

	refreshToken := jwt.New(jwt.GetSigningMethod(config.ServiceJWTSigningMethod.GetString()))
	refreshToken.Header["kid"] = "rt"
	rtClaims := refreshToken.Claims.(jwt.MapClaims)
	rtClaims["refresh_uuid"] = td.RefreshUUID
	rtClaims["user_id"] = claims.UserId
	rtClaims["sub"] = 1
	rtClaims["exp"] = td.RtExpires
	rt, err := refreshToken.SignedString(GetJWTRefreshSigningKey())
	if err != nil {
		return nil, err
	}
	td.RefreshToken = rt

	return td, nil
}

// GetClaimsFromContext gets the JWT claims from the echo context
func GetClaimsFromContext(c echo.Context) *JwtClaims {
	token := c.Get("user").(*jwt.Token)
	claims := token.Claims.(*JwtClaims)
	return claims
}

// GetJWTSigningKey gets the JWT signing key
func GetJWTSigningKey() interface{} {
	if config.ServiceJWTSigningMethod.GetString() == "RS256" {
		var err error
		var f []byte
		var key *rsa.PrivateKey

		f, err = os.ReadFile(config.ServiceJWTSigningKey.GetString())
		if err != nil {
			log.Fatal(err)
		}
		key, err = jwt.ParseRSAPrivateKeyFromPEM(f)
		if err != nil {
			log.Fatal(err)
		}
		return key
	}
	return []byte(config.ServiceJWTSigningSecret.GetString())
}

// GetJWTRefreshSigningKey gets the JWT refresh signing key
func GetJWTRefreshSigningKey() interface{} {
	if config.ServiceJWTSigningMethod.GetString() == "RS256" {
		var err error
		var f []byte
		var key *rsa.PrivateKey

		f, err = os.ReadFile(config.ServiceJWTRefreshSigningKey.GetString())
		if err != nil {
			log.Fatal(err)
		}
		key, err = jwt.ParseRSAPrivateKeyFromPEM(f)
		if err != nil {
			log.Fatal(err)
		}
		return key
	}
	return []byte(config.ServiceJWTRefreshSigningSecret.GetString())
}

// GetJWTPublicKey gets the JWT public key
func GetJWTPublicKey() interface{} {
	if config.ServiceJWTSigningMethod.GetString() == "RS256" {
		var err error
		var f []byte
		var key *rsa.PublicKey

		f, err = os.ReadFile(config.ServiceJWTPublicKey.GetString())
		if err != nil {
			log.Fatal(err)
		}
		key, err = jwt.ParseRSAPublicKeyFromPEM(f)
		if err != nil {
			log.Fatal(err)
		}
		return key
	}

	return []byte(config.ServiceJWTSigningSecret.GetString())
}

// GetEchoJWTConfig returns the echo JWT config
func GetEchoJWTConfig() echojwt.Config {
	return echojwt.Config{
		SigningMethod: config.ServiceJWTSigningMethod.GetString(),
		SigningKey:    GetJWTPublicKey(),
		NewClaimsFunc: func(c echo.Context) jwt.Claims {
			return new(JwtClaims)
		},
	}
}

// GetClaimsFromRefreshToken gets the claims from the refresh token
func GetClaimsFromRefreshToken(refreshToken string) (jwt.MapClaims, error) {
	var token *jwt.Token
	var err error

	if config.ServiceJWTSigningMethod.GetString() == "RS256" {
		token, err = jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			f, ferr := os.ReadFile(config.ServiceJWTRefreshPublicKey.GetString())
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
		token, err = jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(config.ServiceJWTRefreshSigningSecret.GetString()), nil
		})
	}

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, errors.New("refresh token expired")
	}

	claims := token.Claims.(jwt.MapClaims)
	return claims, nil
}
