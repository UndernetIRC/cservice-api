// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package helper

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"

	"github.com/undernetirc/cservice-api/internal/config"
	"github.com/undernetirc/cservice-api/internal/testutils"
	"github.com/undernetirc/cservice-api/models"
)

func TestGenerateToken(t *testing.T) {
	config.DefaultConfig()

	user := new(models.User)
	user.ID = 1000
	user.Username = "test"
	user.TotpKey.String = ""

	var jToken interface{}

	claims := &JwtClaims{
		UserID:   user.ID,
		Username: user.Username,
		Scope:    "admin",
	}
	assert.True(t, claims.HasScope("admin"))
	assert.False(t, claims.HasScope("user"))

	token, err := GenerateToken(claims, time.Now())
	assert.NoError(t, err)

	segment := strings.Split(token.AccessToken, ".")
	assert.Equal(t, 3, len(segment))

	if l := len(segment[1]) % 4; l > 0 {
		segment[1] += strings.Repeat("=", 4-l)
	}
	uPart1, _ := base64.URLEncoding.DecodeString(segment[1])
	if err := json.Unmarshal(uPart1, &jToken); err != nil {
		t.Error(err)
	}

	assert.Equal(t, float64(1000), jToken.(map[string]interface{})["user_id"])
	assert.Equal(t, "test", jToken.(map[string]interface{})["username"])
	assert.Equal(t, "admin", jToken.(map[string]interface{})["scope"])
}

func TestJWT(t *testing.T) {
	config.DefaultConfig()
	claims := new(JwtClaims)
	claims.UserID = 1
	claims.Username = "Admin"
	tokens, _ := GenerateToken(claims, time.Now())
	token, err := jwt.ParseWithClaims(tokens.AccessToken, &JwtClaims{}, func(_ *jwt.Token) (interface{}, error) {
		return GetJWTPublicKey(), nil
	})
	assert.Nil(t, err)

	e := echo.New()
	ctx := e.NewContext(nil, nil)
	ctx.Set("user", token)

	res := GetClaimsFromContext(ctx)
	assert.Equal(t, claims.UserID, res.UserID)
}

func TestJWTWithRSAKeys(t *testing.T) {
	var err error
	var keyFile, publicKeyFile *os.File
	var token *jwt.Token

	keyFile, publicKeyFile, err = testutils.GenerateRSAKeyPair()
	assert.Nil(t, err)

	defer func(name string) {
		err := os.Remove(name)
		if err != nil {
			t.Fatal(err)
		}
	}(keyFile.Name())

	defer func(name string) {
		err := os.Remove(name)
		if err != nil {
			t.Fatal(err)
		}
	}(publicKeyFile.Name())

	config.DefaultConfig()
	config.ServiceJWTSigningMethod.Set("RS256")
	config.ServiceJWTSigningKey.Set(keyFile.Name())
	config.ServiceJWTPublicKey.Set(publicKeyFile.Name())
	config.ServiceJWTRefreshSigningKey.Set(keyFile.Name())
	config.ServiceJWTRefreshPublicKey.Set(publicKeyFile.Name())

	claims := new(JwtClaims)
	claims.UserID = 1
	claims.Username = "Admin"
	tokens, _ := GenerateToken(claims, time.Now())
	token, err = jwt.ParseWithClaims(tokens.AccessToken, &JwtClaims{}, func(_ *jwt.Token) (interface{}, error) {
		return GetJWTPublicKey(), nil
	})
	assert.Nil(t, err)

	e := echo.New()
	ctx := e.NewContext(nil, nil)
	ctx.Set("user", token)

	res := GetClaimsFromContext(ctx)
	assert.Equal(t, claims.UserID, res.UserID)
}
