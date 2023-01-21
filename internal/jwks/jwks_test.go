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

	"github.com/undernetirc/cservice-api/internal/config"
	"gopkg.in/go-playground/assert.v1"
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
	config.Conf = &config.Config{}
	config.Conf.JWT.SigningMethod = "RS256"
	config.Conf.JWT.SigningKey = keyFile.Name()
	config.Conf.JWT.PublicKey = publicKeyFile.Name()
	config.Conf.JWT.RefreshSigningKey = keyFile.Name()
	config.Conf.JWT.RefreshPublicKey = publicKeyFile.Name()

	jwks, err := GenerateJWKS()
	if err != nil {
		t.Fatal(err)
	}

	// Check if the JWKS is valid JSON
	var jwksStruct JWKS
	if err := json.Unmarshal(jwks, &jwksStruct); err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, len(jwksStruct.Keys), 2)
	assert.Equal(t, jwksStruct.Keys[0].Alg, "RS256")
	assert.Equal(t, jwksStruct.Keys[0].Kid, "at")
	assert.Equal(t, jwksStruct.Keys[0].Kty, "oct")
	assert.Equal(t, jwksStruct.Keys[0].Use, "sig")
	assert.Equal(t, jwksStruct.Keys[1].Alg, "RS256")
	assert.Equal(t, jwksStruct.Keys[1].Kid, "rt")
	assert.Equal(t, jwksStruct.Keys[1].Kty, "oct")
	assert.Equal(t, jwksStruct.Keys[1].Use, "sig")
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
