// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

// Package jwks provides functions for generating a JWKS
package jwks

import (
	"encoding/json"
	"os"

	"github.com/golang-jwt/jwt/v5"

	"github.com/go-jose/go-jose/v3"
	"github.com/undernetirc/cservice-api/internal/config"
)

// GenerateJWKS generates a JWKS
func GenerateJWKS() ([]byte, error) {
	atKey, err := os.ReadFile(config.ServiceJWTPublicKey.GetString())
	if err != nil {
		return nil, err
	}
	atRsaPublicKey, err := jwt.ParseRSAPublicKeyFromPEM(atKey)
	if err != nil {
		return nil, err
	}
	rtKey, err := os.ReadFile(config.ServiceJWTRefreshPublicKey.GetString())
	if err != nil {
		return nil, err
	}
	rtRsaPublicKey, err := jwt.ParseRSAPublicKeyFromPEM(rtKey)
	if err != nil {
		return nil, err
	}

	jwks := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{
			Key:       atRsaPublicKey,
			Algorithm: config.ServiceJWTSigningMethod.GetString(),
			Use:       "sig",
			KeyID:     "at",
		},
		{
			Key:       rtRsaPublicKey,
			Algorithm: config.ServiceJWTSigningMethod.GetString(),
			Use:       "sig",
			KeyID:     "rt",
		}},
	}

	return json.Marshal(jwks)
}
