# API Key Authentication Guide

This guide explains how to work with API key authentication in cservice-api controllers, including how to detect authentication type and handle both JWT users and API keys.

## Overview

The cservice-api supports two authentication methods:

1. **JWT Authentication** - Traditional user authentication with access tokens
2. **API Key Authentication** - Service-to-service authentication with scoped permissions

Both authentication methods are handled by the `CombinedAuth` middleware, which tries JWT first and falls back to API key authentication if a JWT is not present.

## Authentication Flow

```
Request → CombinedAuth Middleware → JWT Found? → Yes → Set JWT token in context
                                   ↓
                                   No
                                   ↓
                              API Key Found? → Yes → Set API Key context
                                   ↓
                                   No
                                   ↓
                              Return 401 Unauthorized
```

## Checking Authentication Type in Controllers

### Quick Example

```go
func (ctr *YourController) YourHandler(c echo.Context) error {
    logger := helper.GetRequestLogger(c)
    user := c.Get("user")

    // Check if it's an API key
    if apiKey, ok := user.(*helper.APIKeyContext); ok {
        logger.Info("API key request",
            "keyID", apiKey.ID,
            "name", apiKey.Name,
            "scopes", apiKey.Scopes)
        // Handle API key logic
        return handleAPIKeyRequest(c, apiKey)
    }

    // Check if it's JWT
    if token, ok := user.(*jwt.Token); ok {
        claims := token.Claims.(*helper.JwtClaims)
        logger.Info("JWT request",
            "userID", claims.UserID,
            "username", claims.Username)
        // Handle JWT user logic
        return handleJWTRequest(c, claims)
    }

    return echo.NewHTTPError(http.StatusUnauthorized,
        "Invalid authentication")
}
```

### Using Helper Function

For simpler checks, use the helper function:

```go
func (ctr *YourController) YourHandler(c echo.Context) error {
    // Returns *APIKeyContext if authenticated via API key, nil otherwise
    if apiKey := helper.GetAPIKeyFromContext(c); apiKey != nil {
        // It's an API key
        return handleAPIKeyRequest(c, apiKey)
    }

    // Otherwise it's JWT (or not authenticated)
    claims, err := helper.GetClaims(c)
    if err != nil {
        return echo.NewHTTPError(http.StatusUnauthorized, "Invalid JWT")
    }

    return handleJWTRequest(c, claims)
}
```

## Authentication Context Types

### APIKeyContext

Location: `internal/helper/apikey.go`

```go
type APIKeyContext struct {
    ID       int32    // API key database ID
    Name     string   // Human-readable name
    Scopes   []string // Permitted scopes (e.g., ["users:read", "channels:write"])
    IsAPIKey bool     // Always true for API keys
}
```

**Usage Example:**
```go
if apiKey, ok := user.(*helper.APIKeyContext); ok {
    logger.Info("API key authentication",
        "keyID", apiKey.ID,
        "keyName", apiKey.Name,
        "scopes", apiKey.Scopes)

    // Check if key has specific scope
    if helper.HasRequiredScope(apiKey.Scopes, []string{"users:read"}) {
        // API key has users:read permission
    }
}
```

### JwtClaims

Location: `internal/helper/jwt.go`

```go
type JwtClaims struct {
    UserID   int32    `json:"user_id"`
    Username string   `json:"username"`
    Adm      int32    `json:"adm"`      // Admin level (0-1000)
    Scopes   []string `json:"scopes,omitempty"`
    jwt.RegisteredClaims
}
```

**Usage Example:**
```go
if token, ok := user.(*jwt.Token); ok {
    claims := token.Claims.(*helper.JwtClaims)

    logger.Info("JWT authentication",
        "userID", claims.UserID,
        "username", claims.Username,
        "adminLevel", claims.Adm)

    // Check admin level
    if claims.Adm >= 1000 {
        // User is an admin
    }
}
```

## Complete Controller Example

Here's a full example showing different behavior for API keys vs JWT users:

```go
package controllers

import (
    "net/http"

    "github.com/golang-jwt/jwt/v5"
    "github.com/labstack/echo/v4"
    "github.com/undernetirc/cservice-api/internal/helper"
    "github.com/undernetirc/cservice-api/models"
)

type DataController struct {
    s models.ServiceInterface
}

func NewDataController(s models.ServiceInterface) *DataController {
    return &DataController{s: s}
}

// GetData returns data with different behavior for API keys vs JWT users
func (ctr *DataController) GetData(c echo.Context) error {
    logger := helper.GetRequestLogger(c)
    user := c.Get("user")

    var responseData map[string]interface{}

    // Handle API Key authentication
    if apiKey, ok := user.(*helper.APIKeyContext); ok {
        logger.Info("API key accessing endpoint",
            "keyID", apiKey.ID,
            "keyName", apiKey.Name,
            "scopes", apiKey.Scopes)

        // API keys might have different data access patterns
        // For example, they might not have a specific user context
        responseData = map[string]interface{}{
            "auth_type":  "api_key",
            "api_key_id": apiKey.ID,
            "key_name":   apiKey.Name,
            "scopes":     apiKey.Scopes,
            "message":    "Service-to-service request",
        }

        // You might track API key usage differently
        go ctr.trackAPIKeyUsage(apiKey.ID)

        return c.JSON(http.StatusOK, responseData)
    }

    // Handle JWT authentication
    if token, ok := user.(*jwt.Token); ok {
        claims := token.Claims.(*helper.JwtClaims)

        logger.Info("User accessing endpoint",
            "userID", claims.UserID,
            "username", claims.Username,
            "adminLevel", claims.Adm)

        // JWT users have full user context
        responseData = map[string]interface{}{
            "auth_type":   "jwt",
            "user_id":     claims.UserID,
            "username":    claims.Username,
            "admin_level": claims.Adm,
            "message":     "User request",
        }

        return c.JSON(http.StatusOK, responseData)
    }

    // Neither authentication type found
    return echo.NewHTTPError(http.StatusUnauthorized,
        "Invalid authentication")
}

func (ctr *DataController) trackAPIKeyUsage(keyID int32) {
    // Track API key usage asynchronously
    // e.g., update last_used_at timestamp
}
```

## Common Patterns

### Pattern 1: Different Permissions for API Keys

```go
func (ctr *Controller) DeleteResource(c echo.Context) error {
    user := c.Get("user")

    // API keys cannot delete resources - only JWT users with admin access
    if _, ok := user.(*helper.APIKeyContext); ok {
        return echo.NewHTTPError(http.StatusForbidden,
            "API keys cannot perform delete operations")
    }

    // Check JWT user has admin level
    if token, ok := user.(*jwt.Token); ok {
        claims := token.Claims.(*helper.JwtClaims)
        if claims.Adm < 1000 {
            return echo.NewHTTPError(http.StatusForbidden,
                "Admin access required")
        }
    }

    // Proceed with delete
    return nil
}
```

### Pattern 2: Audit Logging with Auth Type

```go
func (ctr *Controller) UpdateResource(c echo.Context) error {
    logger := helper.GetRequestLogger(c)
    user := c.Get("user")

    var auditInfo map[string]interface{}

    if apiKey, ok := user.(*helper.APIKeyContext); ok {
        auditInfo = map[string]interface{}{
            "auth_type": "api_key",
            "key_id":    apiKey.ID,
            "key_name":  apiKey.Name,
        }
    } else if token, ok := user.(*jwt.Token); ok {
        claims := token.Claims.(*helper.JwtClaims)
        auditInfo = map[string]interface{}{
            "auth_type": "jwt",
            "user_id":   claims.UserID,
            "username":  claims.Username,
        }
    }

    // Update resource...

    // Log the action with authentication context
    logger.Info("Resource updated",
        "resourceID", resourceID,
        "authInfo", auditInfo)

    return nil
}
```

### Pattern 3: Rate Limiting by Auth Type

```go
func (ctr *Controller) ProcessRequest(c echo.Context) error {
    user := c.Get("user")

    var rateLimitKey string

    if apiKey, ok := user.(*helper.APIKeyContext); ok {
        // API keys might have different rate limits
        rateLimitKey = fmt.Sprintf("apikey:%d", apiKey.ID)
    } else if token, ok := user.(*jwt.Token); ok {
        claims := token.Claims.(*helper.JwtClaims)
        rateLimitKey = fmt.Sprintf("user:%d", claims.UserID)
    }

    // Apply rate limiting based on key
    if !checkRateLimit(rateLimitKey) {
        return echo.NewHTTPError(http.StatusTooManyRequests,
            "Rate limit exceeded")
    }

    return nil
}
```

## Scope-Based Authorization

API keys use scopes for fine-grained permissions. Available scopes are defined in `internal/helper/scopes.go`:

```go
// Channel scopes
helper.ScopeChannelsRead    // "channels:read"
helper.ScopeChannelsWrite   // "channels:write"
helper.ScopeChannelsDelete  // "channels:delete"

// User scopes
helper.ScopeUsersRead       // "users:read"
helper.ScopeUsersWrite      // "users:write"
helper.ScopeUsersDelete     // "users:delete"

// Registration scopes
helper.ScopeRegistrationsRead   // "registrations:read"
helper.ScopeRegistrationsWrite  // "registrations:write"
```

### Checking Scopes in Controllers

```go
func (ctr *Controller) ReadUserData(c echo.Context) error {
    user := c.Get("user")

    if apiKey, ok := user.(*helper.APIKeyContext); ok {
        // Check if API key has required scope
        if !helper.HasRequiredScope(apiKey.Scopes, []string{helper.ScopeUsersRead}) {
            return echo.NewHTTPError(http.StatusForbidden,
                "users:read scope required")
        }
    }

    // Proceed with operation
    return nil
}
```

## Middleware Authorization

Most authorization checks are handled automatically by the `HasAuthorization` middleware. You typically don't need to check permissions in controllers if you configure routes correctly:

```go
// In routes/user.go
usersRouter := r.routerGroup.Group("/users")

// Requires admin level 1000 OR users:read scope
usersRouter.GET("/:id", c.GetUser,
    middlewares.HasAuthorization(1000, helper.ScopeUsersRead))

// Requires admin level 1000 OR users:write scope
usersRouter.PUT("/:id", c.UpdateUser,
    middlewares.HasAuthorization(1000, helper.ScopeUsersWrite))
```

### How HasAuthorization Works

The middleware checks authentication type and applies appropriate rules:

- **API Keys**: Must have at least one of the required scopes
- **JWT Users**: Must have admin level >= required level OR one of the required scopes

Example from `middlewares/has_authorization.go`:

```go
// API key authentication - only check scopes
if apiKey, ok := userToken.(*helper.APIKeyContext); ok {
    if len(scopes) > 0 {
        if helper.HasRequiredScope(apiKey.Scopes, scopes) {
            return next(c) // Authorized
        }
        return echo.NewHTTPError(http.StatusForbidden,
            "required scope(s) not found")
    }
    // No scopes but has level requirement - deny API keys
    return echo.NewHTTPError(http.StatusForbidden,
        "this endpoint requires JWT authentication")
}

// JWT authentication - check level OR scopes
if token, ok := userToken.(*jwt.Token); ok {
    claims := token.Claims.(*helper.JwtClaims)

    // Check admin level
    if claims.Adm >= level {
        return next(c) // Authorized by level
    }

    // Check scopes
    if len(scopes) > 0 && helper.HasRequiredScope(claims.Scopes, scopes) {
        return next(c) // Authorized by scope
    }

    return echo.NewHTTPError(http.StatusForbidden,
        "Insufficient permissions")
}
```

## Best Practices

### 1. Always Use Type Assertions Safely

```go
// Good - checks type before using
if apiKey, ok := user.(*helper.APIKeyContext); ok {
    // Safe to use apiKey
}

// Bad - could panic
apiKey := user.(*helper.APIKeyContext)
```

### 2. Log Authentication Context

```go
logger := helper.GetRequestLogger(c)
user := c.Get("user")

if apiKey, ok := user.(*helper.APIKeyContext); ok {
    logger.Info("API key request",
        "keyID", apiKey.ID,
        "operation", "getUser")
} else if token, ok := user.(*jwt.Token); ok {
    claims := token.Claims.(*helper.JwtClaims)
    logger.Info("User request",
        "userID", claims.UserID,
        "operation", "getUser")
}
```

### 3. Use Middleware for Authorization

Prefer route-level authorization over controller-level checks:

```go
// Good - declarative and clear
router.GET("/:id", c.GetUser,
    middlewares.HasAuthorization(1000, helper.ScopeUsersRead))

// Less good - manual checks in controller
func (c *Controller) GetUser(ctx echo.Context) error {
    // Manual authorization checks...
}
```

### 4. Handle Both Auth Types Gracefully

```go
func (ctr *Controller) GetResource(c echo.Context) error {
    user := c.Get("user")

    // Extract common information
    var actorID string
    var actorName string

    if apiKey, ok := user.(*helper.APIKeyContext); ok {
        actorID = fmt.Sprintf("apikey:%d", apiKey.ID)
        actorName = apiKey.Name
    } else if token, ok := user.(*jwt.Token); ok {
        claims := token.Claims.(*helper.JwtClaims)
        actorID = fmt.Sprintf("user:%d", claims.UserID)
        actorName = claims.Username
    }

    // Use common variables for both auth types
    logger.Info("Resource accessed",
        "actorID", actorID,
        "actorName", actorName)

    return nil
}
```

## Testing

### Testing with API Keys

```go
// In integration tests
apiKey := "cserv_your_test_api_key"

r, _ := http.NewRequest("GET", "/api/v1/users/1", nil)
r.Header.Set("X-API-Key", apiKey)

e.ServeHTTP(w, r)
```

### Testing with JWT

```go
// In unit tests
claims := &helper.JwtClaims{
    UserID:   1,
    Username: "testuser",
    Adm:      1000,
}
token, _ := helper.GenerateToken(claims, time.Now())

r, _ := http.NewRequest("GET", "/api/v1/users/1", nil)
r.Header.Set("Authorization", "Bearer "+token.AccessToken)

e.ServeHTTP(w, r)
```

## API Key Headers

API keys are sent in the `X-API-Key` header:

```
GET /api/v1/users/1 HTTP/1.1
Host: api.example.com
X-API-Key: cserv_abcdef123456789...
```

JWT tokens use the standard `Authorization` header:

```
GET /api/v1/users/1 HTTP/1.1
Host: api.example.com
Authorization: Bearer eyJhbGc...
```

## References

- **Combined Auth Middleware**: `middlewares/combined_auth.go`
- **Has Authorization Middleware**: `middlewares/has_authorization.go`
- **API Key Helper**: `internal/helper/apikey.go`
- **Scopes Helper**: `internal/helper/scopes.go`
- **JWT Helper**: `internal/helper/jwt.go`
- **Integration Tests**: `integration/apikey_integration_test.go`
