// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package config

import (
	"crypto/rand"
	"fmt"
	"log"
	"strings"

	"github.com/spf13/viper"
)

type K string

const (
	ServiceHost      K = `service.host`
	ServicePort      K = `service.port`
	ServiceApiPrefix K = `service.api_prefix`

	ServiceJWTSigningMethod     K = `service.jwt.signing_method`
	ServiceJWTSigningSecret     K = `service.jwt.signing_secret`
	ServiceJWTSigningKey        K = `service.jwt.signing_key`
	ServiceJWTPublicKey         K = `service.jwt.public_key`
	ServiceJWTRefreshSecret     K = `service.jwt.refresh_secret`
	ServiceJWTRefreshSigningKey K = `service.jwt.refresh_signing_key`
	ServiceJWTRefreshPublicKey  K = `service.jwt.refresh_public_key`

	DatabaseHost          K = `database.host`
	DatabasePort          K = `database.port`
	DatabaseUsername      K = `database.username`
	DatabasePassword      K = `database.password`
	DatabaseName          K = `database.name`
	DatabaseAutoMigration K = `database.auto_migration`

	RedisHost     K = `redis.host`
	RedisPort     K = `redis.port`
	RedisPassword K = `redis.password`
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

func (k K) Set(value interface{}) {
	viper.Set(string(k), value)
}

func (k K) setDefault(value interface{}) {
	viper.SetDefault(string(k), value)
}

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
	ServiceJWTSigningKey.setDefault(signingKey)
	ServiceJWTRefreshSigningKey.setDefault(refreshKey)

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

func GetServerAddress() string {
	return fmt.Sprintf("%s:%s", ServiceHost.GetString(), ServicePort.GetString())
}

func Random(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%X", b), nil
}
