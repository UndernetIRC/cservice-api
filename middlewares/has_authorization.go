// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package middlewares

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"github.com/undernetirc/cservice-api/internal/helper"

	"github.com/labstack/echo/v4"
)

type HasAuthorizationConfig struct {
	JWTContextKey   string
	AdminLevelClaim string
}

var DefaultHasAuthorizationConfig = HasAuthorizationConfig{
	JWTContextKey:   "user",
	AdminLevelClaim: "adm",
}

func HasAuthorization(level int32, scopes ...string) echo.MiddlewareFunc {
	return HasAuthorizationWithConfig(DefaultHasAuthorizationConfig, level, scopes...)
}

func HasAuthorizationWithConfig(config HasAuthorizationConfig, level int32, scopes ...string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Get user from context
			userToken := c.Get(config.JWTContextKey)
			if userToken == nil {
				return echo.ErrUnauthorized
			}

			// Check if it's an API key
			if apiKey, ok := userToken.(*helper.APIKeyContext); ok {
				// API keys use scope-based authorization only
				if len(scopes) > 0 {
					if helper.HasRequiredScope(apiKey.Scopes, scopes) {
						return next(c)
					}
				} else if level == 0 {
					// If no scopes and no level required, allow access
					return next(c)
				}
				// API keys don't have admin levels, so deny if level > 0 and no matching scopes
				return &echo.HTTPError{
					Code:    http.StatusForbidden,
					Message: fmt.Sprintf("required scope(s) [%s] not found in API key", strings.Join(scopes, ", ")),
				}
			}

			// Check if it's JWT (existing logic)
			user, ok := userToken.(*jwt.Token)
			if !ok {
				return echo.ErrUnauthorized
			}

			adminLevel := user.Claims.(*helper.JwtClaims).Adm
			userScopes := strings.Split(user.Claims.(*helper.JwtClaims).Scope, " ")

			// Admin level always have precedence over scopes if both are defined, 0 disables admin level check
			if level > 0 && adminLevel >= level {
				return next(c)
			} else if len(scopes) > 0 {
				for _, scope := range scopes {
					if helper.InArray(scope, userScopes) {
						return next(c)
					}
				}
			}
			return &echo.HTTPError{
				Code:    http.StatusForbidden,
				Message: fmt.Sprintf("level [%d] or scope(s) [%s] is required to access this resource", level, strings.Join(scopes, ", ")),
			}
		}
	}
}
