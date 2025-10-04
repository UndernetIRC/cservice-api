// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

package middlewares

import (
	"encoding/json"
	"time"

	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/undernetirc/cservice-api/internal/helper"
	"github.com/undernetirc/cservice-api/models"
)

// CombinedAuthConfig configures combined authentication middleware
type CombinedAuthConfig struct {
	// AllowJWT enables JWT authentication from Authorization: Bearer header
	AllowJWT bool
	// AllowAPIKey enables API key authentication from X-API-Key header
	AllowAPIKey bool
	// Required indicates whether authentication is mandatory
	Required bool
	// JWTConfig is the JWT configuration (echojwt.Config)
	JWTConfig echojwt.Config
	// Service provides access to database queries
	Service models.ServiceInterface
}

// DefaultCombinedAuthConfig returns the default combined auth configuration
func DefaultCombinedAuthConfig(service models.ServiceInterface) CombinedAuthConfig {
	return CombinedAuthConfig{
		AllowJWT:    true,
		AllowAPIKey: true,
		Required:    true,
		JWTConfig:   helper.GetEchoJWTConfig(),
		Service:     service,
	}
}

// CombinedAuth returns a middleware that tries JWT authentication first, then API key authentication
func CombinedAuth(config CombinedAuthConfig) echo.MiddlewareFunc {
	// Create JWT middleware
	jwtMiddleware := echojwt.WithConfig(config.JWTConfig)

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Try JWT authentication first
			if config.AllowJWT {
				authHeader := c.Request().Header.Get("Authorization")
				if authHeader != "" {
					// Use JWT middleware
					err := jwtMiddleware(func(c echo.Context) error {
						// JWT succeeded, continue
						return next(c)
					})(c)

					// If JWT succeeded, we're done
					if err == nil {
						return nil
					}
					// JWT failed, but we might try API key next
				}
			}

			// Try API key authentication
			if config.AllowAPIKey {
				apiKey := helper.ExtractAPIKey(c)
				if apiKey != "" {
					// Validate API key
					authenticated, keyContext, err := authenticateAPIKey(c, config.Service, apiKey)
					if err != nil {
						// Log error but don't return it yet (might not be required)
						c.Logger().Warnf("API key authentication error: %v", err)
					} else if authenticated && keyContext != nil {
						// Set context similar to JWT
						c.Set("user", keyContext)
						return next(c)
					}
				}
			}

			// If authentication is required and both methods failed
			if config.Required {
				return echo.ErrUnauthorized
			}

			// Authentication not required, continue
			return next(c)
		}
	}
}

// authenticateAPIKey validates an API key and returns the context if valid
func authenticateAPIKey(c echo.Context, service models.ServiceInterface, plainKey string) (bool, *helper.APIKeyContext, error) {
	// Hash the provided key for database lookup
	keyHash, err := helper.HashAPIKey(plainKey)
	if err != nil {
		return false, nil, err
	}

	// Get the key from database by hash
	apiKey, err := service.GetAPIKeyByHash(c.Request().Context(), keyHash)
	if err != nil {
		// Key not found or error
		return false, nil, err
	}

	// Check expiration
	if apiKey.ExpiresAt.Valid && apiKey.ExpiresAt.Int32 > 0 {
		now := time.Now().Unix()
		if int64(apiKey.ExpiresAt.Int32) < now {
			return false, nil, nil
		}
	}

	// Parse scopes from JSON
	var scopes []string
	if len(apiKey.Scopes) > 0 {
		if err := json.Unmarshal(apiKey.Scopes, &scopes); err != nil {
			return false, nil, err
		}
	}

	// Update last used timestamp (fire and forget, don't block on error)
	go func() {
		_ = service.UpdateAPIKeyLastUsed(c.Request().Context(),
			apiKey.ID,
			helper.Int32ToNullableInt32(int32(time.Now().Unix())),
		)
	}()

	// Create context
	keyContext := &helper.APIKeyContext{
		ID:       apiKey.ID,
		Name:     apiKey.Name,
		Scopes:   scopes,
		IsAPIKey: true,
	}

	return true, keyContext, nil
}
