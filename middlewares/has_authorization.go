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
			user := c.Get(config.JWTContextKey).(*jwt.Token)
			if user == nil {
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
				Code: http.StatusForbidden,
				// TODO: Make the error message a bit more dynamic
				Message: fmt.Sprintf("level [%d] or scope(s) [%s] is required to access this resource", level, strings.Join(scopes, ", ")),
			}
		}
	}
}
