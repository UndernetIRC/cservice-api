// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

// Package testutils provides shared unit test functions
package testutils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
)

// GenerateRSAKeyPair creates a keypair used for unit testing
func GenerateRSAKeyPair() (*os.File, *os.File, error) {
	reader := rand.Reader
	var err error
	var key *rsa.PrivateKey
	var keyFile, publicKeyFile *os.File

	key, err = rsa.GenerateKey(reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	keyFile, err = os.CreateTemp("/tmp", "private.pem")
	if err != nil {
		log.Fatal(err)
	}

	if err = savePrivateKey(keyFile, key); err != nil {
		log.Fatal(err)
	}

	// Public RSA key
	publicKey := key.PublicKey
	publicKeyFile, err = os.CreateTemp("/tmp", "public.pem")
	if err != nil {
		log.Fatal(err)
	}

	if err := savePublicKey(publicKeyFile, &publicKey); err != nil {
		log.Fatal(err)
	}

	return keyFile, publicKeyFile, nil
}

// savePrivateKey saves the private key to a file
func savePrivateKey(f *os.File, key *rsa.PrivateKey) error {
	return pem.Encode(f, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
}

// savePublicKey saves the public key to a file
func savePublicKey(f *os.File, key *rsa.PublicKey) error {
	asn, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		log.Fatal(err)
	}
	return pem.Encode(f, &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: asn,
	})
}
