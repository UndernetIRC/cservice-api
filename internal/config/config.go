// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package config

import (
	"fmt"
	"os"

	"github.com/golang-jwt/jwt"
	"github.com/kelseyhightower/envconfig"
	"gopkg.in/yaml.v3"
)

type Config struct {
	JWT      JWTConfig      `yaml:"jwt"`
	Server   ServerConfig   `yaml:"server"`
	Database DatabaseConfig `yaml:"database"`
	Redis    RedisConfig    `yaml:"redis"`
}

type JWTConfig struct {
	SigningMethod     string `yaml:"signing_method" envconfig:"CSERVICE_JWT_SIGNING_METHOD"`
	SigningKey        string `yaml:"signing_key" envconfig:"CSERVICE_JWT_SIGNING_KEY"`
	PublicKey         string `yaml:"public_key,omitempty" envconfig:"CSERVICE_JWT_PUBLIC_KEY"`
	RefreshSigningKey string `yaml:"refresh_signing_key" envconfig:"CSERVICE_JWT_REFRESH_SIGNING_KEY"`
	RefreshPublicKey  string `yaml:"refresh_public_key,omitempty" envconfig:"CSERVICE_JWT_REFRESH_PUBLIC_KEY"`
}

type ServerConfig struct {
	Host      string `yaml:"host" envconfig:"CSERVICE_SERVER_HOST"`
	Port      string `yaml:"port" envconfig:"CSERVICE_SERVER_PORT"`
	ApiPrefix string `yaml:"api_prefix" envconfig:"CSERVICE_SERVER_API_PREFIX"`
}

type DatabaseConfig struct {
	Host          string `yaml:"host" envconfig:"CSERVICE_DB_HOST"`
	Port          uint   `yaml:"port" envconfig:"CSERVICE_DB_PORT"`
	Username      string `yaml:"username" envconfig:"CSERVICE_DB_USERNAME"`
	Password      string `yaml:"password" envconfig:"CSERVICE_DB_PASSWORD"`
	Name          string `yaml:"name" envconfig:"CSERVICE_DB_NAME"`
	AutoMigration bool   `yaml:"auto_migration" envconfig:"CSERVICE_DB_AUTOMIGRATION"`
}

type RedisConfig struct {
	Host              string `yaml:"host" envconfig:"CSERVICE_REDIS_HOST"`
	Port              uint   `yaml:"port" envconfig:"CSERVICE_REDIS_PORT"`
	Password          string `yaml:"password" envconfig:"CSERVICE_REDIS_PASSWORD"`
	Database          int    `yaml:"database" envconfig:"CSERVICE_REDIS_DATABASE"`
	EnableMultiLogout bool   `yaml:"enable_multi_logout" envconfig:"CSERVICE_REDIS_ENABLE_MULTI_LOGOUT"`
}

var Conf *Config

func LoadConfig(configFile *string) {
	Conf = &Config{}
	Conf.readConfigFile(configFile)
	Conf.readEnvVariables()
	Conf.validateConfig()
}

func (c *Config) GetDbURI() string {
	return fmt.Sprintf(
		"postgres://%s:%s@%s:%d/%s?sslmode=disable",
		c.Database.Username,
		c.Database.Password,
		c.Database.Host,
		c.Database.Port,
		c.Database.Name,
	)
}

func (c *Config) GetJWTSigningKey() interface{} {
	if c.JWT.SigningMethod == "RS256" {
		f, err := os.ReadFile(c.JWT.SigningKey)
		if err != nil {
			panic(err)
		}
		key, err := jwt.ParseRSAPrivateKeyFromPEM(f)
		if err != nil {
			panic(err)
		}
		return key
	}

	return []byte(c.JWT.SigningKey)
}

func (c *Config) GetJWTPublicKey() interface{} {
	if c.JWT.SigningMethod == "RS256" {
		f, err := os.ReadFile(c.JWT.PublicKey)
		if err != nil {
			panic(err)
		}
		key, err := jwt.ParseRSAPublicKeyFromPEM(f)
		if err != nil {
			panic(err)
		}
		return key
	}

	return []byte(c.JWT.SigningKey)
}

func (c *Config) GetJWTRefreshSigningKey() interface{} {
	if c.JWT.SigningMethod == "RS256" {
		f, err := os.ReadFile(c.JWT.RefreshSigningKey)
		if err != nil {
			panic(err)
		}
		key, err := jwt.ParseRSAPrivateKeyFromPEM(f)
		if err != nil {
			panic(err)
		}
		return key
	}

	return []byte(c.JWT.SigningKey)
}

func printError(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}

func closeFile(f *os.File) {
	err := f.Close()

	if err != nil {
		printError(err)
	}
}

func (c *Config) readConfigFile(configFile *string) {
	f, err := os.Open(*configFile)
	defer closeFile(f)
	if err != nil {
		printError(err)
	} else {
		d := yaml.NewDecoder(f)
		err = d.Decode(c)
		if err != nil {
			printError(err)
		}
	}
}

func (c *Config) readEnvVariables() {
	err := envconfig.Process("", c)
	if err != nil {
		printError(err)
	}
}

func (c *Config) validateConfig() {
	//TODO: not yet implemented
}
