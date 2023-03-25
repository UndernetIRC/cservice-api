// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

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
	// ServiceApiPrefix is the prefix to use for the API set to "" for /
	ServiceApiPrefix K = `service.api_prefix`

	// ServiceJWTSigningMethod is the signing method to use for JWT
	ServiceJWTSigningMethod K = `service.jwt.signing_method`
	// ServiceJWTSigningSecret is the secret to use for JWT (only for HS256)
	ServiceJWTSigningSecret K = `service.jwt.signing_secret`
	// ServiceJWTSigningKey is the key to use for JWT (only for RS256)
	ServiceJWTSigningKey K = `service.jwt.signing_key`
	// ServiceJWTPublicKey is the public key to use for JWT (only for RS256)
	ServiceJWTPublicKey K = `service.jwt.public_key`
	// ServiceJWTRefreshSigningSecret is the secret to use for JWT refresh token (only for HS256)
	ServiceJWTRefreshSigningSecret K = `service.jwt.refresh_signing_secret`
	// ServiceJWTRefreshSigningKey is the key to use for JWT refresh token (only for RS256)
	ServiceJWTRefreshSigningKey K = `service.jwt.refresh_signing_key`
	// ServiceJWTRefreshPublicKey is the public key to use for JWT refresh token (only for RS256)
	ServiceJWTRefreshPublicKey K = `service.jwt.refresh_public_key`

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
)

// Get returns the raw value of the key
func (k K) Get() interface{} {
	return viper.Get(string(k))
}

// GetString returns the value of the key as a string
func (k K) GetString() string {
	return viper.GetString(string(k))
}

// GetBool returns the value of the key as a bool
func (k K) GetBool() bool {
	return viper.GetBool(string(k))
}

// GetInt returns the value of the key as an int
func (k K) GetInt() int {
	return viper.GetInt(string(k))
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
	ServiceApiPrefix.setDefault("api")

	ServiceJWTSigningMethod.setDefault("HS256")
	ServiceJWTSigningSecret.setDefault(signingKey)
	ServiceJWTRefreshSigningSecret.setDefault(refreshKey)

	DatabaseHost.setDefault("localhost")
	DatabasePort.setDefault(3306)
	DatabaseUsername.setDefault("cservice")
	DatabasePassword.setDefault("cservice")
	DatabaseName.setDefault("cservice")
	DatabaseAutoMigration.setDefault(true)

	RedisHost.setDefault("localhost")
	RedisPort.setDefault(6379)
	RedisPassword.setDefault("")
	RedisDatabase.setDefault(0)
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
