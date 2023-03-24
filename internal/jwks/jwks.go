// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

// Package jwks provides functions for generating a JWKS
package jwks

import (
	"encoding/json"
	"encoding/pem"
	"os"

	jose "github.com/go-jose/go-jose/v3"
	"github.com/undernetirc/cservice-api/internal/config"
)

// GenerateJWKS generates a JWKS
func GenerateJWKS() ([]byte, error) {
	atKey, _ := os.ReadFile(config.ServiceJWTPublicKey.GetString())
	atPem, _ := pem.Decode(atKey)
	atJWK := jose.JSONWebKey{Key: atPem.Bytes, Algorithm: config.ServiceJWTSigningMethod.GetString(), Use: "sig", KeyID: "at"}
	rtKey, _ := os.ReadFile(config.ServiceJWTRefreshPublicKey.GetString())
	rtPem, _ := pem.Decode(rtKey)
	rtJWK := jose.JSONWebKey{Key: rtPem.Bytes, Algorithm: config.ServiceJWTSigningMethod.GetString(), Use: "sig", KeyID: "rt"}
	pubJWKS := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{atJWK, rtJWK}}

	pubJSJWKS, err := json.Marshal(pubJWKS)
	if err != nil {
		return nil, err
	}

	return pubJSJWKS, nil
}
