// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023-2024 UnderNET

package config

import (
	"net/url"
	"os"
	"strconv"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	viper.Reset()

	DatabaseHost.Set("test-host")
	DatabasePort.Set("5432")
	DatabaseUsername.Set("test-user")
	DatabasePassword.Set("test-pass")
	DatabaseName.Set("test-db")

	tests := []struct {
		name        string
		password    string // defaults to "test-pass" when empty
		sslMode     string
		sslRootCert string
		sslCert     string
		sslKey      string
		want        string
	}{
		{
			name:    "default sslmode disable produces the pre-existing URI byte-for-byte",
			sslMode: "disable",
			want:    "postgres://test-user:test-pass@test-host:5432/test-db?sslmode=disable",
		},
		{
			// Regression: "openssl rand -base64 32" (README's recommended
			// recipe) emits from [A-Za-z0-9+/=], so roughly half of generated
			// passwords contain a "/". Unescaped, that truncated the authority
			// and pgx rejected the DSN with "invalid port".
			name:     "password containing base64 characters is escaped",
			password: "ab/cd+ef=",
			sslMode:  "disable",
			want:     "postgres://test-user:ab%2Fcd+ef=@test-host:5432/test-db?sslmode=disable",
		},
		{
			name:     "password containing URI delimiters is escaped",
			password: "p@ss:w/rd?#x",
			sslMode:  "disable",
			want:     "postgres://test-user:p%40ss%3Aw%2Frd%3F%23x@test-host:5432/test-db?sslmode=disable",
		},
		{
			name:        "verify-full with cert material appends URL-encoded paths",
			sslMode:     "verify-full",
			sslRootCert: "/etc/ssl/ca.crt",
			sslCert:     "/etc/ssl/client.crt",
			sslKey:      "/etc/ssl/client.key",
			want: "postgres://test-user:test-pass@test-host:5432/test-db?" +
				"sslcert=%2Fetc%2Fssl%2Fclient.crt&sslkey=%2Fetc%2Fssl%2Fclient.key&" +
				"sslmode=verify-full&sslrootcert=%2Fetc%2Fssl%2Fca.crt",
		},
		{
			name:        "require with only root cert set omits unset client cert paths",
			sslMode:     "require",
			sslRootCert: "/etc/ssl/ca.crt",
			want: "postgres://test-user:test-pass@test-host:5432/test-db?" +
				"sslmode=require&sslrootcert=%2Fetc%2Fssl%2Fca.crt",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			password := tt.password
			if password == "" {
				password = "test-pass"
			}
			DatabasePassword.Set(password)
			DatabaseSSLMode.Set(tt.sslMode)
			DatabaseSSLRootCert.Set(tt.sslRootCert)
			DatabaseSSLCert.Set(tt.sslCert)
			DatabaseSSLKey.Set(tt.sslKey)

			got := GetDbURI()
			assert.Equal(t, tt.want, got)

			// The DSN is only useful if pgx can parse it back; pgx uses
			// url.Parse for postgres:// URLs.
			u, err := url.Parse(got)
			require.NoError(t, err)
			gotPassword, _ := u.User.Password()
			assert.Equal(t, password, gotPassword, "password must survive a parse round-trip")
			assert.Equal(t, "test-host:5432", u.Host)
			assert.Equal(t, "/test-db", u.Path)
		})
	}
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
