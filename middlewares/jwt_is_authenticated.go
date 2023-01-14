package middlewares

import (
	"github.com/golang-jwt/jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/undernetirc/cservice-api/internal/helper"
	"net/http"
)

func JWTIsAuthenticated(next echo.HandlerFunc) echo.HandlerFunc {
	return echo.HandlerFunc(func(c echo.Context) error {
		token := c.Get("user").(*jwt.Token)
		claims := token.Claims.(*helper.JwtClaims)
		if claims.Authenticated {
			return next(c)
		}
		return echo.NewHTTPError(http.StatusUnauthorized, "OTP authentication required")
	})
}
