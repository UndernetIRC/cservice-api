// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023-2024 UnderNET

package config

import (
	"os"
	"strconv"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestKTypeMethods(t *testing.T) {
	// Reset viper before each test
	viper.Reset()

	tests := []struct {
		name     string
		key      K
		setValue interface{}
		getFunc  func(K) interface{}
		want     interface{}
	}{
		{
			name:     "GetString",
			key:      ServiceHost,
			setValue: "test-host",
			getFunc:  func(k K) interface{} { return k.GetString() },
			want:     "test-host",
		},
		{
			name:     "GetStringSlice",
			key:      ServiceCorsAllowOrigins,
			setValue: []string{"http://localhost", "https://localhost"},
			getFunc:  func(k K) interface{} { return k.GetStringSlice() },
			want:     []string{"http://localhost", "https://localhost"},
		},
		{
			name:     "GetBool",
			key:      ServiceDevMode,
			setValue: true,
			getFunc:  func(k K) interface{} { return k.GetBool() },
			want:     true,
		},
		{
			name:     "GetInt",
			key:      ServicePort,
			setValue: 8080,
			getFunc:  func(k K) interface{} { return k.GetInt() },
			want:     8080,
		},
		{
			name:     "GetUint",
			key:      ServicePort,
			setValue: uint(8080),
			getFunc:  func(k K) interface{} { return k.GetUint() },
			want:     uint(8080),
		},
		{
			name:     "GetUint8",
			key:      ServiceTotpSkew,
			setValue: uint8(1),
			getFunc:  func(k K) interface{} { return k.GetUint8() },
			want:     uint8(1),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.key.Set(tt.setValue)
			got := tt.getFunc(tt.key)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	// Reset viper before test
	viper.Reset()

	// Run DefaultConfig
	DefaultConfig()

	// Test some default values
	assert.Equal(t, "*", ServiceHost.GetString())
	assert.Equal(t, 8080, ServicePort.GetInt())
	assert.Equal(t, "api", ServiceAPIPrefix.GetString())
	assert.Equal(t, "HS256", ServiceJWTSigningMethod.GetString())
	assert.Equal(t, uint8(1), ServiceTotpSkew.GetUint8())
	assert.Equal(t, []string{"*"}, ServiceCorsAllowOrigins.GetStringSlice())
	assert.Equal(t, []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}, ServiceCorsAllowMethods.GetStringSlice())
	assert.True(t, ServiceCorsAllowCredentials.GetBool())
	assert.Equal(t, 0, ServiceCorsMaxAge.GetInt())
	assert.False(t, ServiceCookieSameSiteNone.GetBool())
	assert.Equal(t, "localhost", DatabaseHost.GetString())
	assert.Equal(t, 5432, DatabasePort.GetInt())
	assert.Equal(t, "cservice", DatabaseUsername.GetString())
	assert.Equal(t, "cservice", DatabasePassword.GetString())
	assert.Equal(t, "cservice", DatabaseName.GetString())
	assert.True(t, DatabaseAutoMigration.GetBool())
	assert.Equal(t, "localhost", RedisHost.GetString())
	assert.Equal(t, 6379, RedisPort.GetInt())
	assert.Equal(t, "", RedisPassword.GetString())
	assert.Equal(t, 0, RedisDatabase.GetInt())
	assert.Equal(t, "localhost", SMTPHost.GetString())
	assert.Equal(t, 1025, SMTPPort.GetInt())
	assert.Equal(t, "", SMTPUsername.GetString())
	assert.Equal(t, "", SMTPPassword.GetString())
	assert.False(t, SMTPUseTLS.GetBool())
	assert.Equal(t, "noreply@cservice.undernet.org", SMTPFromEmail.GetString())
	assert.Equal(t, "UnderNET CService", SMTPFromName.GetString())
	assert.True(t, ServiceMailEnabled.GetBool())
	assert.Equal(t, 5, ServiceMailWorkers.GetInt())
	assert.False(t, ServiceDevMode.GetBool())
}

func TestInitConfig(t *testing.T) {
	// Reset viper before test
	viper.Reset()

	// Create a temporary config file
	tmpFile, err := os.CreateTemp("", "config-*.yaml")
	assert.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	// Write some test config
	configContent := []byte(`
service:
  host: "test-host"
  port: 9090
  api_prefix: "test-api"
`)
	err = os.WriteFile(tmpFile.Name(), configContent, 0o644)
	assert.NoError(t, err)

	// Run InitConfig with the temp file
	InitConfig(tmpFile.Name())

	// Test that the values were loaded
	assert.Equal(t, "test-host", ServiceHost.GetString())
	assert.Equal(t, 9090, ServicePort.GetInt())
	assert.Equal(t, "test-api", ServiceAPIPrefix.GetString())
}

func TestGetDbURI(t *testing.T) {
	// Reset viper before test
	viper.Reset()

	// Set test values
	DatabaseHost.Set("test-host")
	DatabasePort.Set("5432")
	DatabaseUsername.Set("test-user")
	DatabasePassword.Set("test-pass")
	DatabaseName.Set("test-db")

	// Get the URI
	uri := GetDbURI()

	// Test the URI format
	expectedURI := "postgres://test-user:test-pass@test-host:5432/test-db?sslmode=disable"
	assert.Equal(t, expectedURI, uri)
}

func TestGetServerAddress(t *testing.T) {
	// Reset viper before test
	viper.Reset()

	// Set test values
	ServiceHost.Set("test-host")
	ServicePort.Set("8080")

	// Get the server address
	addr := GetServerAddress()

	// Test the address format
	expectedAddr := "test-host:8080"
	assert.Equal(t, expectedAddr, addr)
}

func TestRandom(t *testing.T) {
	// Test different lengths
	lengths := []int{10, 20, 40}

	for _, length := range lengths {
		t.Run("length_"+strconv.Itoa(length), func(t *testing.T) {
			// Generate random string
			str, err := Random(length)
			assert.NoError(t, err)
			assert.Len(t, str, length*2) // Because it's hex encoded
		})
	}

	// Test error case with invalid length
	_, err := Random(-1)
	assert.Error(t, err)
}

func TestParseCorsEnvList(t *testing.T) {
	viper.Reset()

	os.Setenv("CSERVICE_SERVICE_CORS_ALLOWED_ORIGINS", "test test2")
	expected := []string{"test", "test2"}

	InitConfig("")

	assert.Equal(t, expected, ServiceCorsAllowOrigins.GetStringSlice())
	assert.True(t, len(ServiceCorsAllowOrigins.GetStringSlice()) == 2)
}
