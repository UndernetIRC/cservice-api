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
	// ServiceBaseURL is the base URL of the service
	ServiceBaseURL K = `service.base_url`
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

	// ReCAPTCHA configuration
	// ServiceReCAPTCHAEnabled enables or disables reCAPTCHA verification
	ServiceReCAPTCHAEnabled K = `service.recaptcha.enabled`
	// ServiceReCAPTCHASecretKey is the secret key for reCAPTCHA verification
	ServiceReCAPTCHASecretKey K = `service.recaptcha.secret_key`
	// ServiceReCAPTCHAMinScore is the minimum score threshold for reCAPTCHA verification (0.0 to 1.0)
	ServiceReCAPTCHAMinScore K = `service.recaptcha.min_score`
	// ServiceReCAPTCHAFieldName is the field name in the JSON payload containing the reCAPTCHA token
	ServiceReCAPTCHAFieldName K = `service.recaptcha.field_name`

	// CORS configuration
	// ServiceCorsAllowedOrigins is the list of allowed origins
	ServiceCorsAllowOrigins K = `service.cors.allowed_origins`
	// ServiceCorsAllowMethods is the list of allowed methods
	ServiceCorsAllowMethods K = `service.cors.allow_methods`
	// ServviceCorsCredentials is whether to allow credentials in a CORS request
	ServiceCorsAllowCredentials K = `service.cors.allow_credentials`
	// ServiceCorsMaxAge is the max age of the CORS response
	ServiceCorsMaxAge K = `service.cors.max_age`

	// Cookie options
	// ServiceCookieSameSiteNone is whether to set SameSite=None in a cookie
	ServiceCookieSameSiteNone K = `service.cookie.same_site_none`

	// ServiceMailEnabled controls whether the mail service is enabled
	ServiceMailEnabled K = `service.mail.enabled`
	// ServiceMailWorkers is the number of mail worker goroutines to run
	ServiceMailWorkers K = `service.mail.workers`
	// ServiceMailTemplateDir is the directory containing email templates
	ServiceMailTemplateDir K = `service.mail.template_dir`
	// ServiceMailDefaultTemplate is the default template to use for emails
	ServiceMailDefaultTemplate K = `service.mail.default_template`

	// ServiceShutdownTimeoutSeconds is the timeout in seconds for graceful shutdown
	ServiceShutdownTimeoutSeconds K = `service.shutdown_timeout_seconds`

	// HTTP Server timeout configurations
	// ServiceHTTPReadHeaderTimeoutSeconds is the timeout for reading request headers
	ServiceHTTPReadHeaderTimeoutSeconds K = `service.http.read_header_timeout_seconds`
	// ServiceHTTPReadTimeoutSeconds is the timeout for reading the entire request
	ServiceHTTPReadTimeoutSeconds K = `service.http.read_timeout_seconds`
	// ServiceHTTPWriteTimeoutSeconds is the timeout for writing the response
	ServiceHTTPWriteTimeoutSeconds K = `service.http.write_timeout_seconds` //nolint:gosec // G101: This is a configuration key, not a credential
	// ServiceHTTPIdleTimeoutSeconds is the timeout for keep-alive connections
	ServiceHTTPIdleTimeoutSeconds K = `service.http.idle_timeout_seconds`

	// ServiceDevMode indicates if the service is running in development mode
	ServiceDevMode K = `service.dev_mode`
	// ServicePendingUserExpirationHours is the number of hours a pending user registration is valid
	ServicePendingUserExpirationHours K = `service.pending_user_expiration_hours`
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

	// Password Reset Token configuration
	// ServicePasswordResetTokenLength is the length of generated password reset tokens
	ServicePasswordResetTokenLength K = `service.password_reset.token_length`
	// ServicePasswordResetTokenLifetimeMinutes is how long password reset tokens are valid in minutes
	ServicePasswordResetTokenLifetimeMinutes K = `service.password_reset.token_lifetime_minutes`
	// ServicePasswordResetCleanupIntervalHours is how often to clean up expired tokens in hours
	ServicePasswordResetCleanupIntervalHours K = `service.password_reset.cleanup_interval_hours`
	// ServicePasswordResetMaxTokensPerUser is the maximum number of active tokens per user
	ServicePasswordResetMaxTokensPerUser K = `service.password_reset.max_tokens_per_user`

	// Cron configuration
	// ServiceCronEnabled controls whether the cron service is enabled
	ServiceCronEnabled K = `service.cron.enabled`
	// ServiceCronPasswordResetCleanup is the cron expression for password reset token cleanup
	ServiceCronPasswordResetCleanup K = `service.cron.password_reset_cleanup`
	// ServiceCronTimeZone is the timezone for cron jobs
	ServiceCronTimeZone K = `service.cron.timezone`

	// OpenTelemetry configuration
	// TelemetryEnabled controls whether OpenTelemetry is enabled
	TelemetryEnabled K = `telemetry.enabled`
	// TelemetryServiceName is the service name for OpenTelemetry
	TelemetryServiceName K = `telemetry.service_name`
	// TelemetryServiceVersion is the service version for OpenTelemetry
	TelemetryServiceVersion K = `telemetry.service_version`
	// TelemetryOTLPEndpoint is the OTLP exporter endpoint
	TelemetryOTLPEndpoint K = `telemetry.otlp.endpoint`
	// TelemetryOTLPHeaders are the headers for OTLP exporter
	TelemetryOTLPHeaders K = `telemetry.otlp.headers`
	// TelemetryOTLPInsecure controls whether to use insecure OTLP connection
	TelemetryOTLPInsecure K = `telemetry.otlp.insecure`
	// TelemetryPrometheusEnabled controls whether Prometheus metrics are enabled
	TelemetryPrometheusEnabled K = `telemetry.prometheus.enabled`
	// TelemetryPrometheusEndpoint is the Prometheus metrics endpoint path
	TelemetryPrometheusEndpoint K = `telemetry.prometheus.endpoint`
	// TelemetryJaegerEnabled controls whether Jaeger tracing is enabled
	TelemetryJaegerEnabled K = `telemetry.jaeger.enabled`
	// TelemetryJaegerEndpoint is the Jaeger endpoint
	TelemetryJaegerEndpoint K = `telemetry.jaeger.endpoint`
	// TelemetryTracingEnabled controls whether distributed tracing is enabled
	TelemetryTracingEnabled K = `telemetry.tracing.enabled`
	// TelemetryTracingSampleRate is the trace sampling rate (0.0 to 1.0)
	TelemetryTracingSampleRate K = `telemetry.tracing.sample_rate`
	// TelemetryMetricsEnabled controls whether metrics collection is enabled
	TelemetryMetricsEnabled K = `telemetry.metrics.enabled`
	// TelemetryMetricsInterval is the metrics collection interval in seconds
	TelemetryMetricsInterval K = `telemetry.metrics.interval`
	// TelemetryResourceAttributes are additional resource attributes
	TelemetryResourceAttributes K = `telemetry.resource.attributes`
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

// GetUInt64 returns the value of the key as an uint64
func (k K) GetInt64() int64 {
	return viper.GetInt64(string(k))
}

// GetUint8 returns the value of the key as an uint8
func (k K) GetUint8() uint8 {
	return viper.GetUint8(string(k))
}

// GetFloat64 returns the value of the key as a float64
func (k K) GetFloat64() float64 {
	return viper.GetFloat64(string(k))
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

	ServiceHost.setDefault("*")
	ServicePort.setDefault(8080)
	ServiceBaseURL.setDefault("http://localhost:8080")
	ServiceAPIPrefix.setDefault("api")

	ServiceJWTSigningMethod.setDefault("HS256")
	ServiceJWTSigningSecret.setDefault(signingKey)
	ServiceJWTRefreshSigningSecret.setDefault(refreshKey)

	ServiceTotpSkew.setDefault(uint8(1))

	// ReCAPTCHA defaults
	ServiceReCAPTCHAEnabled.setDefault(false)
	ServiceReCAPTCHASecretKey.setDefault("")
	ServiceReCAPTCHAMinScore.setDefault(0.5)
	ServiceReCAPTCHAFieldName.setDefault("recaptcha_token")

	ServiceCorsAllowOrigins.setDefault([]string{"*"})
	ServiceCorsAllowMethods.setDefault([]string{"GET", "POST", "PUT", "DELETE", "OPTIONS"})
	ServiceCorsAllowCredentials.setDefault(true)
	ServiceCorsMaxAge.setDefault(0)

	// Cookie options
	ServiceCookieSameSiteNone.setDefault(false)

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
	SMTPPort.setDefault(1025)
	SMTPUsername.setDefault("")
	SMTPPassword.setDefault("")
	SMTPUseTLS.setDefault(false)
	SMTPFromEmail.setDefault("noreply@cservice.undernet.org")
	SMTPFromName.setDefault("UnderNET CService")

	// Default mail settings
	ServiceMailEnabled.setDefault(true)
	ServiceMailWorkers.setDefault(5)
	ServiceMailTemplateDir.setDefault("")
	ServiceMailDefaultTemplate.setDefault("default")

	// Default to false for development mode
	ServiceDevMode.setDefault(false)

	// Default pending user expiration to 2 hours
	ServicePendingUserExpirationHours.setDefault(2)

	// Default shutdown timeout to 10 seconds
	ServiceShutdownTimeoutSeconds.setDefault(10)

	// Default HTTP server timeouts
	ServiceHTTPReadHeaderTimeoutSeconds.setDefault(30)
	ServiceHTTPReadTimeoutSeconds.setDefault(60)
	ServiceHTTPWriteTimeoutSeconds.setDefault(60)
	ServiceHTTPIdleTimeoutSeconds.setDefault(90)

	// Password Reset Token defaults
	ServicePasswordResetTokenLength.setDefault(32)
	ServicePasswordResetTokenLifetimeMinutes.setDefault(60) // 1 hour
	ServicePasswordResetCleanupIntervalHours.setDefault(24) // 24 hours
	ServicePasswordResetMaxTokensPerUser.setDefault(3)

	// Cron configuration
	// ServiceCronEnabled controls whether the cron service is enabled
	ServiceCronEnabled.setDefault(false)
	// ServiceCronPasswordResetCleanup is the cron expression for password reset token cleanup
	ServiceCronPasswordResetCleanup.setDefault("0 0 * * *")
	// ServiceCronTimeZone is the timezone for cron jobs
	ServiceCronTimeZone.setDefault("UTC")

	// OpenTelemetry defaults
	TelemetryEnabled.setDefault(true)
	TelemetryServiceName.setDefault("cservice-api")
	TelemetryServiceVersion.setDefault("1.0.0")
	TelemetryOTLPEndpoint.setDefault("")
	TelemetryOTLPHeaders.setDefault(map[string]string{})
	TelemetryOTLPInsecure.setDefault(false)
	TelemetryPrometheusEnabled.setDefault(true)
	TelemetryPrometheusEndpoint.setDefault("/metrics")
	TelemetryJaegerEnabled.setDefault(false)
	TelemetryJaegerEndpoint.setDefault("")
	TelemetryTracingEnabled.setDefault(true)
	TelemetryTracingSampleRate.setDefault(0.1)
	TelemetryMetricsEnabled.setDefault(true)
	TelemetryMetricsInterval.setDefault(30)
	TelemetryResourceAttributes.setDefault(map[string]string{})
}

// InitConfig initializes the configuration
func InitConfig(configFile string) {
	// Set default values
	DefaultConfig()

	// Check environment variables
	viper.SetEnvPrefix("cservice")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	// Read config file
	if configFile != "" {
		viper.SetConfigFile(configFile)
	} else {
		viper.AddConfigPath("/etc/cservice-api")
		viper.AddConfigPath(".")
		viper.SetConfigName("config")
	}
	err := viper.ReadInConfig()
	if viper.ConfigFileUsed() != "" {
		if err != nil {
			log.Println(err.Error())
		}
	} else {
		log.Printf("No config file found (tried %s), using default settings or environment variables", viper.ConfigFileUsed())
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
	if ServiceHost.GetString() == "*" {
		return fmt.Sprintf(":%s", ServicePort.GetString())
	}
	return fmt.Sprintf("%s:%s", ServiceHost.GetString(), ServicePort.GetString())
}

// Random returns a random string of the given length
func Random(length int) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("length must be positive, got %d", length)
	}
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%X", b), nil
}
