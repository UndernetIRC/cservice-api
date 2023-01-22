// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package helper

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/undernetirc/cservice-api/internal/config"
	"github.com/undernetirc/cservice-api/models"
	"gopkg.in/go-playground/assert.v1"
)

func TestGenerateToken(t *testing.T) {
	config.Conf = &config.Config{}
	config.Conf.JWT.SigningMethod = "HS256"
	config.Conf.JWT.SigningKey = "hirkumpirkum"

	user := new(models.User)
	user.ID = 1000
	user.UserName = "test"
	user.TotpKey = nil

	var jToken interface{}

	claims := &JwtClaims{
		UserId:   user.ID,
		Username: user.UserName,
	}

	token, err := GenerateToken(claims)

	if err != nil {
		t.Error(err)
	}

	segment := strings.Split(token.AccessToken, ".")
	if len(segment) != 3 {
		t.Error("Invalid token")
	}

	if l := len(segment[1]) % 4; l > 0 {
		segment[1] += strings.Repeat("=", 4-l)
	}
	uPart1, _ := base64.URLEncoding.DecodeString(segment[1])
	if err := json.Unmarshal(uPart1, &jToken); err != nil {
		t.Error(err)
	}

	assert.Equal(t, float64(1000), jToken.(map[string]interface{})["user_id"])
	assert.Equal(t, "test", jToken.(map[string]interface{})["username"])
}
