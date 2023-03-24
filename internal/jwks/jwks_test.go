// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package jwks

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"testing"

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
	reader := rand.Reader

	// Private RSA key
	key, err := rsa.GenerateKey(reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyFile, err := os.CreateTemp("/tmp", "private.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(keyFile.Name())
	if err := savePrivateKey(keyFile, key); err != nil {
		t.Fatal(err)
	}

	// Public RSA key
	publicKey := key.PublicKey
	publicKeyFile, err := os.CreateTemp("/tmp", "public.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(publicKeyFile.Name())
	if err := savePublicKey(publicKeyFile, &publicKey); err != nil {
		t.Fatal(err)
	}

	// Setup config for GenerateJWKS
	config.DefaultConfig()
	config.ServiceJWTSigningMethod.Set("RS256")
	config.ServiceJWTSigningKey.Set(keyFile.Name())
	config.ServiceJWTPublicKey.Set(publicKeyFile.Name())
	config.ServiceJWTRefreshSigningKey.Set(keyFile.Name())
	config.ServiceJWTRefreshPublicKey.Set(publicKeyFile.Name())

	jwks, err := GenerateJWKS()
	if err != nil {
		t.Fatal(err)
	}

	// Check if the JWKS is valid JSON
	var jwksStruct JWKS
	if err := json.Unmarshal(jwks, &jwksStruct); err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, 2, len(jwksStruct.Keys))
	assert.Equal(t, "RS256", jwksStruct.Keys[0].Alg)
	assert.Equal(t, "at", jwksStruct.Keys[0].Kid)
	assert.Equal(t, "oct", jwksStruct.Keys[0].Kty)
	assert.Equal(t, "sig", jwksStruct.Keys[0].Use)
	assert.Equal(t, "RS256", jwksStruct.Keys[1].Alg)
	assert.Equal(t, "rt", jwksStruct.Keys[1].Kid)
	assert.Equal(t, "oct", jwksStruct.Keys[1].Kty)
	assert.Equal(t, "sig", jwksStruct.Keys[1].Use)
}

func savePrivateKey(f *os.File, key *rsa.PrivateKey) error {
	return pem.Encode(f, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
}

func savePublicKey(f *os.File, key *rsa.PublicKey) error {
	asn1Bytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return err
	}
	return pem.Encode(f, &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: asn1Bytes,
	})
}
