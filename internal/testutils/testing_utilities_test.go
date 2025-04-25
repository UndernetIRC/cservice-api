// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2024 UnderNET

package testutils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"os"
	"testing"
)

func TestGenerateRSAKeyPair(t *testing.T) {
	// Call the function to generate key pair
	privateKeyFile, publicKeyFile, err := GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	// Ensure files are cleaned up after test
	defer os.Remove(privateKeyFile.Name())
	defer os.Remove(publicKeyFile.Name())
	defer privateKeyFile.Close()
	defer publicKeyFile.Close()

	// Check if files exist and are not empty
	privateStat, err := privateKeyFile.Stat()
	if err != nil {
		t.Fatalf("Failed to stat private key file: %v", err)
	}
	if privateStat.Size() == 0 {
		t.Error("Private key file is empty")
	}

	publicStat, err := publicKeyFile.Stat()
	if err != nil {
		t.Fatalf("Failed to stat public key file: %v", err)
	}
	if publicStat.Size() == 0 {
		t.Error("Public key file is empty")
	}

	// Verify the files contain valid PEM data
	privateKeyData, err := os.ReadFile(privateKeyFile.Name())
	if err != nil {
		t.Fatalf("Failed to read private key file: %v", err)
	}

	privatePem, _ := pem.Decode(privateKeyData)
	if privatePem == nil {
		t.Fatal("Failed to decode private key PEM data")
	}
	if privatePem.Type != "PRIVATE KEY" {
		t.Errorf("Private key has incorrect type: got %s, want PRIVATE KEY", privatePem.Type)
	}

	// Try to parse the private key
	_, err = x509.ParsePKCS1PrivateKey(privatePem.Bytes)
	if err != nil {
		t.Errorf("Failed to parse private key: %v", err)
	}

	// Verify public key
	publicKeyData, err := os.ReadFile(publicKeyFile.Name())
	if err != nil {
		t.Fatalf("Failed to read public key file: %v", err)
	}

	publicPem, _ := pem.Decode(publicKeyData)
	if publicPem == nil {
		t.Fatal("Failed to decode public key PEM data")
	}
	if publicPem.Type != "PUBLIC KEY" {
		t.Errorf("Public key has incorrect type: got %s, want PUBLIC KEY", publicPem.Type)
	}

	// Try to parse the public key
	_, err = x509.ParsePKIXPublicKey(publicPem.Bytes)
	if err != nil {
		t.Errorf("Failed to parse public key: %v", err)
	}
}

func TestSavePrivateKey(t *testing.T) {
	// Create a temporary file for the test
	tempFile, err := os.CreateTemp("/tmp", "test_private.pem")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

	// Generate a test key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Save the private key
	err = savePrivateKey(tempFile, privateKey)
	if err != nil {
		t.Fatalf("Failed to save private key: %v", err)
	}

	// Reset file pointer to beginning
	_, err = tempFile.Seek(0, io.SeekStart)
	if err != nil {
		t.Fatalf("Failed to reset file pointer: %v", err)
	}

	// Read the file and verify it contains a valid PEM encoded private key
	data, err := io.ReadAll(tempFile)
	if err != nil {
		t.Fatalf("Failed to read key file: %v", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("Failed to decode PEM block")
	}
	if block.Type != "PRIVATE KEY" {
		t.Errorf("Incorrect block type: got %s, want PRIVATE KEY", block.Type)
	}

	parsedKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse private key: %v", err)
	}

	// Verify the parsed key matches the original
	if parsedKey.N.Cmp(privateKey.N) != 0 {
		t.Error("Parsed key does not match original key")
	}
}

func TestSavePublicKey(t *testing.T) {
	// Create a temporary file for the test
	tempFile, err := os.CreateTemp("/tmp", "test_public.pem")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

	// Generate a test key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	publicKey := &privateKey.PublicKey

	// Save the public key
	err = savePublicKey(tempFile, publicKey)
	if err != nil {
		t.Fatalf("Failed to save public key: %v", err)
	}

	// Reset file pointer to beginning
	_, err = tempFile.Seek(0, io.SeekStart)
	if err != nil {
		t.Fatalf("Failed to reset file pointer: %v", err)
	}

	// Read the file and verify it contains a valid PEM encoded public key
	data, err := io.ReadAll(tempFile)
	if err != nil {
		t.Fatalf("Failed to read key file: %v", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("Failed to decode PEM block")
	}
	if block.Type != "PUBLIC KEY" {
		t.Errorf("Incorrect block type: got %s, want PUBLIC KEY", block.Type)
	}

	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse public key: %v", err)
	}

	// Check if we got an RSA public key
	parsedPublicKey, ok := parsedKey.(*rsa.PublicKey)
	if !ok {
		t.Fatal("Parsed key is not an RSA public key")
	}

	// Verify the parsed key matches the original
	if parsedPublicKey.N.Cmp(publicKey.N) != 0 {
		t.Error("Parsed key does not match original key")
	}
}
