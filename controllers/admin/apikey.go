// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

package admin

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	apierrors "github.com/undernetirc/cservice-api/internal/errors"
	"github.com/undernetirc/cservice-api/internal/helper"
	"github.com/undernetirc/cservice-api/models"
)

type APIKeyController struct {
	s models.Querier
}

func NewAPIKeyController(s models.Querier) *APIKeyController {
	return &APIKeyController{s: s}
}

// CreateAPIKeyRequest represents the request to create a new API key
type CreateAPIKeyRequest struct {
	Name        string   `json:"name"                 validate:"required,min=3,max=255"`
	Description string   `json:"description"          validate:"max=1000"`
	Scopes      []string `json:"scopes"               validate:"required,min=1"`
	ExpiresAt   *int32   `json:"expires_at,omitempty"`
}

// CreateAPIKeyResponse represents the response when creating an API key
type CreateAPIKeyResponse struct {
	ID        int32    `json:"id"`
	Name      string   `json:"name"`
	Key       string   `json:"key"` // Only shown once!
	Scopes    []string `json:"scopes"`
	CreatedAt int32    `json:"created_at"`
	ExpiresAt *int32   `json:"expires_at,omitempty"`
	Warning   string   `json:"warning"`
}

// APIKeyResponse represents an API key without the actual key value
type APIKeyResponse struct {
	ID          int32    `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Scopes      []string `json:"scopes"`
	CreatedBy   int32    `json:"created_by"`
	CreatedAt   int32    `json:"created_at"`
	LastUsedAt  *int32   `json:"last_used_at,omitempty"`
	ExpiresAt   *int32   `json:"expires_at,omitempty"`
}

// UpdateAPIKeyScopesRequest represents the request to update API key scopes
type UpdateAPIKeyScopesRequest struct {
	Scopes []string `json:"scopes" validate:"required,min=1"`
}

// CreateAPIKey creates a new API key
// @Summary Create new API key
// @Description Creates a new API key with specified scopes. The plain key is returned only once.
// @Tags admin
// @Accept json
// @Produce json
// @Param request body CreateAPIKeyRequest true "API key details"
// @Success 201 {object} CreateAPIKeyResponse
// @Security JWTBearerToken
// @Router /admin/api-keys [post]
func (ctr *APIKeyController) CreateAPIKey(c echo.Context) error {
	logger := helper.GetRequestLogger(c)

	// Get the authenticated user
	claims := helper.GetClaimsFromContext(c)
	if claims == nil {
		return apierrors.HandleUnauthorizedError(c, "Authentication required")
	}

	// Parse request
	var req CreateAPIKeyRequest
	if err := c.Bind(&req); err != nil {
		return apierrors.HandleBadRequestError(c, "Invalid request format")
	}

	// Validate request
	if err := c.Validate(&req); err != nil {
		return apierrors.HandleValidationError(c, err)
	}

	// Validate scopes
	if err := helper.ValidateScopes(req.Scopes); err != nil {
		return apierrors.HandleBadRequestError(c, err.Error())
	}

	// Generate API key
	plainKey, err := helper.GenerateAPIKey()
	if err != nil {
		logger.Error("Failed to generate API key", "error", err.Error())
		return apierrors.HandleInternalError(c, err, "Failed to generate API key")
	}

	// Hash the key
	keyHash, err := helper.HashAPIKey(plainKey)
	if err != nil {
		logger.Error("Failed to hash API key", "error", err.Error())
		return apierrors.HandleInternalError(c, err, "Failed to process API key")
	}

	// Marshal scopes to JSON
	scopesJSON, err := json.Marshal(req.Scopes)
	if err != nil {
		logger.Error("Failed to marshal scopes", "error", err.Error())
		return apierrors.HandleInternalError(c, err, "Failed to process scopes")
	}

	// Create API key in database
	now := helper.SafeInt32FromInt64(time.Now().Unix())
	apiKey, err := ctr.s.CreateAPIKey(c.Request().Context(), models.CreateAPIKeyParams{
		Name:        req.Name,
		Description: helper.StringToNullableText(req.Description),
		KeyHash:     keyHash,
		Scopes:      scopesJSON,
		CreatedBy:   claims.UserID,
		CreatedAt:   now,
		LastUpdated: now,
	})
	if err != nil {
		logger.Error("Failed to create API key", "error", err.Error())
		return apierrors.HandleInternalError(c, err, "Failed to create API key")
	}

	// Prepare response
	response := CreateAPIKeyResponse{
		ID:        apiKey.ID,
		Name:      apiKey.Name,
		Key:       plainKey, // Only time the plain key is returned!
		Scopes:    req.Scopes,
		CreatedAt: apiKey.CreatedAt,
		Warning:   "This key will only be shown once. Store it securely.",
	}

	if req.ExpiresAt != nil {
		response.ExpiresAt = req.ExpiresAt
	}

	logger.Info("API key created", "keyID", apiKey.ID, "name", apiKey.Name)

	return c.JSON(http.StatusCreated, response)
}

// ListAPIKeys lists all active API keys
// @Summary List API keys
// @Description Returns all active API keys (without the actual key values)
// @Tags admin
// @Produce json
// @Success 200 {array} APIKeyResponse
// @Security JWTBearerToken
// @Router /admin/api-keys [get]
func (ctr *APIKeyController) ListAPIKeys(c echo.Context) error {
	logger := helper.GetRequestLogger(c)

	keys, err := ctr.s.ListAPIKeys(c.Request().Context())
	if err != nil {
		logger.Error("Failed to list API keys", "error", err.Error())
		return apierrors.HandleInternalError(c, err, "Failed to retrieve API keys")
	}

	// Convert to response format
	responses := make([]APIKeyResponse, len(keys))
	for i, key := range keys {
		var scopes []string
		if len(key.Scopes) > 0 {
			if err := json.Unmarshal(key.Scopes, &scopes); err != nil {
				logger.Warn("Failed to unmarshal scopes for key", "keyID", key.ID)
				scopes = []string{}
			}
		}

		responses[i] = APIKeyResponse{
			ID:          key.ID,
			Name:        key.Name,
			Description: helper.NullableTextToString(key.Description),
			Scopes:      scopes,
			CreatedBy:   key.CreatedBy,
			CreatedAt:   key.CreatedAt,
			LastUsedAt:  helper.NullableInt32ToInt32Ptr(key.LastUsedAt),
			ExpiresAt:   helper.NullableInt32ToInt32Ptr(key.ExpiresAt),
		}
	}

	return c.JSON(http.StatusOK, responses)
}

// ScopeInfo represents information about an API scope
type ScopeInfo struct {
	Scope       string `json:"scope"`
	Resource    string `json:"resource"`
	Action      string `json:"action"`
	Description string `json:"description"`
}

// GetAvailableScopes returns all available API scopes
// @Summary Get available API scopes
// @Description Returns a list of all available API scopes that can be assigned to API keys
// @Tags admin
// @Produce json
// @Success 200 {array} ScopeInfo
// @Security JWTBearerToken
// @Router /admin/api-keys/scopes [get]
func (ctr *APIKeyController) GetAvailableScopes(c echo.Context) error {
	scopes := helper.AllScopes()

	// Build response with additional metadata
	scopeInfos := make([]ScopeInfo, 0, len(scopes))

	for _, scope := range scopes {
		// Parse scope into resource:action format
		parts := splitScope(scope)
		scopeInfos = append(scopeInfos, ScopeInfo{
			Scope:       scope,
			Resource:    parts[0],
			Action:      parts[1],
			Description: helper.GetScopeDescription(scope),
		})
	}

	return c.JSON(http.StatusOK, scopeInfos)
}

// splitScope splits a scope string into [resource, action]
func splitScope(scope string) [2]string {
	for i := 0; i < len(scope); i++ {
		if scope[i] == ':' {
			return [2]string{scope[:i], scope[i+1:]}
		}
	}
	return [2]string{scope, ""}
}

// GetAPIKey returns a specific API key by ID
// @Summary Get API key
// @Description Returns details of a specific API key (without the actual key value)
// @Tags admin
// @Produce json
// @Param id path int true "API Key ID"
// @Success 200 {object} APIKeyResponse
// @Security JWTBearerToken
// @Router /admin/api-keys/{id} [get]
func (ctr *APIKeyController) GetAPIKey(c echo.Context) error {
	logger := helper.GetRequestLogger(c)

	id, err := helper.SafeAtoi32(c.Param("id"))
	if err != nil {
		return apierrors.HandleBadRequestError(c, "Invalid API key ID")
	}

	key, err := ctr.s.GetAPIKey(c.Request().Context(), id)
	if err != nil {
		logger.Error("Failed to get API key", "keyID", id, "error", err.Error())
		return apierrors.HandleNotFoundError(c, "API key")
	}

	var scopes []string
	if len(key.Scopes) > 0 {
		if err := json.Unmarshal(key.Scopes, &scopes); err != nil {
			logger.Warn("Failed to unmarshal scopes", "keyID", key.ID)
			scopes = []string{}
		}
	}

	response := APIKeyResponse{
		ID:          key.ID,
		Name:        key.Name,
		Description: helper.NullableTextToString(key.Description),
		Scopes:      scopes,
		CreatedBy:   key.CreatedBy,
		CreatedAt:   key.CreatedAt,
		LastUsedAt:  helper.NullableInt32ToInt32Ptr(key.LastUsedAt),
		ExpiresAt:   helper.NullableInt32ToInt32Ptr(key.ExpiresAt),
	}

	return c.JSON(http.StatusOK, response)
}

// UpdateAPIKeyScopes updates the scopes of an API key
// @Summary Update API key scopes
// @Description Updates the permission scopes for an API key
// @Tags admin
// @Accept json
// @Produce json
// @Param id path int true "API Key ID"
// @Param request body UpdateAPIKeyScopesRequest true "New scopes"
// @Success 200 {object} APIKeyResponse
// @Security JWTBearerToken
// @Router /admin/api-keys/{id}/scopes [put]
func (ctr *APIKeyController) UpdateAPIKeyScopes(c echo.Context) error {
	logger := helper.GetRequestLogger(c)

	id, err := helper.SafeAtoi32(c.Param("id"))
	if err != nil {
		return apierrors.HandleBadRequestError(c, "Invalid API key ID")
	}

	var req UpdateAPIKeyScopesRequest
	if err := c.Bind(&req); err != nil {
		return apierrors.HandleBadRequestError(c, "Invalid request format")
	}

	if err := c.Validate(&req); err != nil {
		return apierrors.HandleValidationError(c, err)
	}

	// Validate scopes
	if err := helper.ValidateScopes(req.Scopes); err != nil {
		return apierrors.HandleBadRequestError(c, err.Error())
	}

	// Marshal scopes
	scopesJSON, err := json.Marshal(req.Scopes)
	if err != nil {
		logger.Error("Failed to marshal scopes", "error", err.Error())
		return apierrors.HandleInternalError(c, err, "Failed to process scopes")
	}

	// Update scopes
	err = ctr.s.UpdateAPIKeyScopes(c.Request().Context(), models.UpdateAPIKeyScopesParams{
		ID:          id,
		Scopes:      scopesJSON,
		LastUpdated: helper.SafeInt32FromInt64(time.Now().Unix()),
	})
	if err != nil {
		logger.Error("Failed to update API key scopes", "keyID", id, "error", err.Error())
		return apierrors.HandleInternalError(c, err, "Failed to update API key scopes")
	}

	logger.Info("API key scopes updated", "keyID", id)

	// Return updated key
	return ctr.GetAPIKey(c)
}

// DeleteAPIKey soft-deletes an API key
// @Summary Delete API key
// @Description Soft-deletes an API key, making it unusable
// @Tags admin
// @Produce json
// @Param id path int true "API Key ID"
// @Success 204 "No Content"
// @Security JWTBearerToken
// @Router /admin/api-keys/{id} [delete]
func (ctr *APIKeyController) DeleteAPIKey(c echo.Context) error {
	logger := helper.GetRequestLogger(c)

	id, err := helper.SafeAtoi32(c.Param("id"))
	if err != nil {
		return apierrors.HandleBadRequestError(c, "Invalid API key ID")
	}

	err = ctr.s.DeleteAPIKey(c.Request().Context(), id, helper.SafeInt32FromInt64(time.Now().Unix()))
	if err != nil {
		logger.Error("Failed to delete API key", "keyID", id, "error", err.Error())
		return apierrors.HandleInternalError(c, err, "Failed to delete API key")
	}

	logger.Info("API key deleted", "keyID", id)

	return c.NoContent(http.StatusNoContent)
}
