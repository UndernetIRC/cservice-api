// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023-2024 UnderNET

// Package config provides configuration management
package config

import (
	"crypto/rand"
	"fmt"
	"log"
	"strings"

	"github.com/spf13/viper"
)

// K is a type alias for string
type K string

const (
	// ServiceHost is the host to bind the service to
	ServiceHost K = `service.host`
	// ServicePort is the port to bind the service to
	ServicePort K = `service.port`
	// ServiceAPIPrefix is the prefix to use for the API set to "" for /
	ServiceAPIPrefix K = `service.api_prefix`

	// ServiceJWTSigningMethod is the signing method to use for JWT
	ServiceJWTSigningMethod K = `service.jwt.signing_method`
	// ServiceJWTSigningSecret is the secret to use for JWT (only for HS256)
	//nolint:gosec // False positive: this is a configuration key name, not a credential
	ServiceJWTSigningSecret K = `service.jwt.signing_secret`
	// ServiceJWTSigningKey is the key to use for JWT (only for RS256)
	ServiceJWTSigningKey K = `service.jwt.signing_key`
	// ServiceJWTPublicKey is the public key to use for JWT (only for RS256)
	ServiceJWTPublicKey K = `service.jwt.public_key`
	// ServiceJWTRefreshSigningSecret is the secret to use for JWT refresh token (only for HS256)
	//nolint:gosec // False positive: this is a configuration key name, not a credential
	ServiceJWTRefreshSigningSecret K = `service.jwt.refresh_signing_secret`
	// ServiceJWTRefreshSigningKey is the key to use for JWT refresh token (only for RS256)
	ServiceJWTRefreshSigningKey K = `service.jwt.refresh_signing_key`
	// ServiceJWTRefreshPublicKey is the public key to use for JWT refresh token (only for RS256)
	ServiceJWTRefreshPublicKey K = `service.jwt.refresh_public_key`

	// TotpSkew is the skew to use for TOTP (max 255)
	ServiceTotpSkew K = `service.totp.skew`

	// CORS configuration
	// ServiceCorsAllowedOrigins is the list of allowed origins
	ServiceCorsAllowOrigins K = `service.cors.allowed_origins`
	// ServiceCorsAllowMethods is the list of allowed methods
	ServiceCorsAllowMethods K = `service.cors.allow_methods`
	// ServiceCorsMaxAge is the max age of the CORS response
	ServiceCorsMaxAge K = `service.cors.max_age`

	// DatabaseHost is the host to connect to the database
	DatabaseHost K = `database.host`
	// DatabasePort is the port to connect to the database
	DatabasePort K = `database.port`
	// DatabaseUsername is the username to connect to the database
	DatabaseUsername K = `database.username`
	// DatabasePassword is the password to connect to the database
	DatabasePassword K = `database.password`
	// DatabaseName is the name of the database to connect to
	DatabaseName K = `database.name`
	// DatabaseAutoMigration is whether to automatically apply the migrations to the database
	DatabaseAutoMigration K = `database.auto_migration`

	// RedisHost is the host to connect to the redis
	RedisHost K = `redis.host`
	// RedisPort is the port to connect to the redis
	RedisPort K = `redis.port`
	// RedisPassword is the password to connect to the redis
	RedisPassword K = `redis.password`
	// RedisDatabase is the database to connect to the redis
	RedisDatabase K = `redis.database`

	// SMTPHost is the host of the SMTP server
	SMTPHost K = `smtp.host`
	// SMTPPort is the port of the SMTP server
	SMTPPort K = `smtp.port`
	// SMTPUsername is the username for SMTP authentication
	SMTPUsername K = `smtp.username`
	// SMTPPassword is the password for SMTP authentication
	SMTPPassword K = `smtp.password`
	// SMTPUseTLS determines if TLS should be used for SMTP
	SMTPUseTLS K = `smtp.use_tls`
	// SMTPFromEmail is the default from email address
	SMTPFromEmail K = `smtp.from_email`
	// SMTPFromName is the default from name
	SMTPFromName K = `smtp.from_name`

	// ServiceMailEnabled controls whether the mail service is enabled
	ServiceMailEnabled K = `service.mail.enabled`
	// ServiceMailWorkers is the number of mail worker goroutines to run
	ServiceMailWorkers K = `service.mail.workers`

	// ServiceDevMode indicates if the service is running in development mode
	ServiceDevMode K = `service.dev_mode`
)

// Get returns the raw value of the key
func (k K) Get() interface{} {
	return viper.Get(string(k))
}

// GetString returns the value of the key as a string
func (k K) GetString() string {
	return viper.GetString(string(k))
}

// GetStringSlice returns the value of the key as a string slice
func (k K) GetStringSlice() []string {
	return viper.GetStringSlice(string(k))
}

// GetBool returns the value of the key as a bool
func (k K) GetBool() bool {
	return viper.GetBool(string(k))
}

// GetInt returns the value of the key as an int
func (k K) GetInt() int {
	return viper.GetInt(string(k))
}

// GetInt returns the value of the key as an int
func (k K) GetUint() uint {
	return viper.GetUint(string(k))
}

// GetUint8 returns the value of the key as an uint8
func (k K) GetUint8() uint8 {
	return viper.GetUint8(string(k))
}

// Set sets the value of the key
func (k K) Set(value interface{}) {
	viper.Set(string(k), value)
}

// setDefault sets the default value of the key
func (k K) setDefault(value interface{}) {
	viper.SetDefault(string(k), value)
}

// DefaultConfig sets the default values for the configuration
func DefaultConfig() {
	signingKey, err := Random(40)
	if err != nil {
		log.Fatal(err)
	}
	refreshKey, err := Random(40)
	if err != nil {
		log.Fatal(err)
	}

	ServiceHost.setDefault("localhost")
	ServicePort.setDefault(8080)
	ServiceAPIPrefix.setDefault("api")

	ServiceJWTSigningMethod.setDefault("HS256")
	ServiceJWTSigningSecret.setDefault(signingKey)
	ServiceJWTRefreshSigningSecret.setDefault(refreshKey)

	ServiceTotpSkew.setDefault(uint8(1))

	ServiceCorsAllowOrigins.setDefault([]string{"*"})
	ServiceCorsAllowMethods.setDefault([]string{"GET", "POST", "PUT", "DELETE", "OPTIONS"})
	ServiceCorsMaxAge.setDefault(0)

	DatabaseHost.setDefault("localhost")
	DatabasePort.setDefault(5432)
	DatabaseUsername.setDefault("cservice")
	DatabasePassword.setDefault("cservice")
	DatabaseName.setDefault("cservice")
	DatabaseAutoMigration.setDefault(true)

	RedisHost.setDefault("localhost")
	RedisPort.setDefault(6379)
	RedisPassword.setDefault("")
	RedisDatabase.setDefault(0)

	SMTPHost.setDefault("localhost")
	SMTPPort.setDefault(1025) // Default to a common mailhog port for development
	SMTPUsername.setDefault("")
	SMTPPassword.setDefault("")
	SMTPUseTLS.setDefault(false)
	SMTPFromEmail.setDefault("noreply@cservice.undernet.org")
	SMTPFromName.setDefault("UnderNET CService")

	// Default mail settings
	ServiceMailEnabled.setDefault(true) // Enable mail by default
	ServiceMailWorkers.setDefault(5)    // Default to 5 workers

	// Default to false for development mode
	ServiceDevMode.setDefault(false)
}

// InitConfig initializes the configuration
func InitConfig(path string) {
	// Set default values
	DefaultConfig()

	// Check environment variables
	viper.SetEnvPrefix("cservice")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	// Read config file
	if path != "" {
		viper.AddConfigPath(path)
	}
	viper.AddConfigPath("/etc/cservice-api")
	viper.AddConfigPath(".")
	viper.SetConfigName("config")

	err := viper.ReadInConfig()
	if viper.ConfigFileUsed() != "" {
		log.Printf("Using config file: %s", viper.ConfigFileUsed())
		if err != nil {
			log.Println(err.Error())
		}
	} else {
		log.Println("No config file found, using default settings or environment variables")
	}
}

// GetDbURI returns a database connection string
func GetDbURI() string {
	// TODO: add SSL configuration support
	return fmt.Sprintf(
		"postgres://%s:%s@%s:%s/%s?sslmode=disable",
		DatabaseUsername.GetString(),
		DatabasePassword.GetString(),
		DatabaseHost.GetString(),
		DatabasePort.GetString(),
		DatabaseName.GetString(),
	)
}

// GetServerAddress returns the address string to bind the service to
func GetServerAddress() string {
	return fmt.Sprintf("%s:%s", ServiceHost.GetString(), ServicePort.GetString())
}

// Random returns a random string of the given length
func Random(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%X", b), nil
}
