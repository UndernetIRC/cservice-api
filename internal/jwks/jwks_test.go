// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package jwks

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/undernetirc/cservice-api/internal/testutils"

	"github.com/stretchr/testify/assert"

	"github.com/undernetirc/cservice-api/internal/config"
)

// JWKS struct
type JWKS struct {
	Keys []JWK
}

// JWK struct
type JWK struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	K   string `json:"k"`
}

func TestGenerateJWKS(t *testing.T) {
	var err error
	var keyFile, publicKeyFile *os.File
	var jwks []byte

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

	// Setup config for GenerateJWKS
	config.DefaultConfig()
	config.ServiceJWTSigningMethod.Set("RS256")
	config.ServiceJWTSigningKey.Set(keyFile.Name())
	config.ServiceJWTPublicKey.Set(publicKeyFile.Name())
	config.ServiceJWTRefreshSigningKey.Set(keyFile.Name())
	config.ServiceJWTRefreshPublicKey.Set(publicKeyFile.Name())

	jwks, err = GenerateJWKS()
	assert.Nil(t, err)

	// Check if the JWKS is valid JSON
	var jwksStruct JWKS
	err = json.Unmarshal(jwks, &jwksStruct)
	assert.Nil(t, err)
	assert.Equal(t, 2, len(jwksStruct.Keys))
	assert.Equal(t, "RS256", jwksStruct.Keys[0].Alg)
	assert.Equal(t, "at", jwksStruct.Keys[0].Kid)
	assert.Equal(t, "RSA", jwksStruct.Keys[0].Kty)
	assert.Equal(t, "sig", jwksStruct.Keys[0].Use)
	assert.Equal(t, "RS256", jwksStruct.Keys[1].Alg)
	assert.Equal(t, "rt", jwksStruct.Keys[1].Kid)
	assert.Equal(t, "RSA", jwksStruct.Keys[1].Kty)
	assert.Equal(t, "sig", jwksStruct.Keys[1].Use)
}
