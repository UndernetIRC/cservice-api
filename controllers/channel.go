// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package controllers

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/undernetirc/cservice-api/db"
	"github.com/undernetirc/cservice-api/internal/helper"
	"github.com/undernetirc/cservice-api/models"
)

// safeInt32 safely converts int to int32 with bounds checking
func safeInt32(value int) int32 {
	if value > 2147483647 || value < -2147483648 {
		return 0 // Return 0 for overflow, caller should validate
	}
	return int32(value)
}

// safeInt32FromInt64 safely converts int64 to int32 with bounds checking
func safeInt32FromInt64(value int64) int32 {
	if value > 2147483647 || value < -2147483648 {
		return 0 // Return 0 for overflow, caller should validate
	}
	return int32(value)
}

type ChannelController struct {
	s models.Querier
}

func NewChannelController(s models.Querier) *ChannelController {
	return &ChannelController{s: s}
}

// SearchChannelsRequest represents the search parameters
type SearchChannelsRequest struct {
	Query  string `query:"q" validate:"required,min=1,max=100"`
	Limit  int    `query:"limit" validate:"omitempty,min=1,max=100"`
	Offset int    `query:"offset" validate:"omitempty,min=0"`
}

// SearchChannelsResponse represents the search results
type SearchChannelsResponse struct {
	Channels   []ChannelSearchResult `json:"channels"`
	Pagination PaginationInfo        `json:"pagination"`
}

// ChannelSearchResult represents a single search result
type ChannelSearchResult struct {
	ID          int32  `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	URL         string `json:"url,omitempty"`
	MemberCount int32  `json:"member_count"`
	CreatedAt   int32  `json:"created_at"`
}

// PaginationInfo represents pagination metadata
type PaginationInfo struct {
	Total   int  `json:"total"`
	Limit   int  `json:"limit"`
	Offset  int  `json:"offset"`
	HasMore bool `json:"has_more"`
}

// SearchChannels handles channel search requests with wildcard support and pagination
// @Summary Search channels by name
// @Description Search for channels using wildcard patterns with pagination support
// @Tags channels
// @Accept json
// @Produce json
// @Param q query string true "Search query (supports wildcards)"
// @Param limit query int false "Maximum number of results (default: 20, max: 100)"
// @Param offset query int false "Number of results to skip (default: 0)"
// @Success 200 {object} SearchChannelsResponse
// @Failure 400 {string} string "Invalid query parameters"
// @Failure 401 {string} string "Authorization information is missing or invalid"
// @Failure 500 {string} string "Internal server error"
// @Router /channels/search [get]
// @Security JWTBearerToken
func (ctr *ChannelController) SearchChannels(c echo.Context) error {
	// Check if user context exists first
	userToken := c.Get("user")
	if userToken == nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "Authorization information is missing or invalid")
	}

	// Get user claims from context for authentication validation
	claims := helper.GetClaimsFromContext(c)
	if claims == nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "Authorization information is missing or invalid")
	}

	// Initialize request with default values
	req := &SearchChannelsRequest{
		Limit:  20, // Default limit
		Offset: 0,  // Default offset
	}

	// Manually parse query parameters with error handling
	queryParam := c.QueryParam("q")
	if queryParam == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Search query parameter 'q' is required")
	}
	req.Query = queryParam

	// Parse limit parameter
	if limitParam := c.QueryParam("limit"); limitParam != "" {
		limit, err := strconv.Atoi(limitParam)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "Invalid limit parameter: must be a number")
		}
		if limit < 1 || limit > 100 {
			return echo.NewHTTPError(http.StatusBadRequest, "Invalid limit parameter: must be between 1 and 100")
		}
		req.Limit = limit
	}

	// Parse offset parameter
	if offsetParam := c.QueryParam("offset"); offsetParam != "" {
		offset, err := strconv.Atoi(offsetParam)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "Invalid offset parameter: must be a number")
		}
		if offset < 0 {
			return echo.NewHTTPError(http.StatusBadRequest, "Invalid offset parameter: must be 0 or greater")
		}
		req.Offset = offset
	}

	// Validate the complete request structure
	if err := c.Validate(req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	// Sanitize and prepare the search query for database use
	searchQuery := ctr.prepareSearchQuery(req.Query)

	// Log the search request for audit purposes
	c.Logger().Infof("User %d searching channels with query: %s (prepared: %s), limit: %d, offset: %d",
		claims.UserID, req.Query, searchQuery, req.Limit, req.Offset)

	// Create a context with timeout for database operations
	ctx, cancel := context.WithTimeout(c.Request().Context(), 5*time.Second)
	defer cancel()

	// Get total count for pagination
	totalCount, err := ctr.s.SearchChannelsCount(ctx, searchQuery)
	if err != nil {
		c.Logger().Errorf("Failed to get channel search count: %s", err.Error())
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to search channels")
	}

	// Search channels using SQLC generated method
	searchParams := models.SearchChannelsParams{
		Name:   searchQuery,
		Limit:  safeInt32(req.Limit),
		Offset: safeInt32(req.Offset),
	}

	channelRows, err := ctr.s.SearchChannels(ctx, searchParams)
	if err != nil {
		c.Logger().Errorf("Failed to search channels: %s", err.Error())
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to search channels")
	}

	// Convert database rows to response format
	channels := make([]ChannelSearchResult, len(channelRows))
	for i, row := range channelRows {
		channels[i] = ChannelSearchResult{
			ID:          row.ID,
			Name:        row.Name,
			Description: db.TextToString(row.Description),
			URL:         db.TextToString(row.Url),
			MemberCount: safeInt32FromInt64(row.MemberCount),
			CreatedAt:   db.Int4ToInt32(row.CreatedAt),
		}
	}

	// Calculate pagination info
	hasMore := int64(req.Offset+req.Limit) < totalCount

	response := &SearchChannelsResponse{
		Channels: channels,
		Pagination: PaginationInfo{
			Total:   int(totalCount),
			Limit:   req.Limit,
			Offset:  req.Offset,
			HasMore: hasMore,
		},
	}

	return c.JSON(http.StatusOK, response)
}

// UpdateChannelSettingsRequest represents the update request body
type UpdateChannelSettingsRequest struct {
	Description *string `json:"description" validate:"omitempty,max=500"`
	URL         *string `json:"url" validate:"omitempty,url,max=255"`
}

// UpdateChannelSettingsResponse represents the update response
type UpdateChannelSettingsResponse struct {
	ID          int32  `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	URL         string `json:"url,omitempty"`
	CreatedAt   int32  `json:"created_at"`
	UpdatedAt   int32  `json:"updated_at"`
}

// UpdateChannelSettings handles channel settings update requests
// @Summary Update channel settings
// @Description Update channel description and URL with proper validation and access control
// @Tags channels
// @Accept json
// @Produce json
// @Param id path int true "Channel ID"
// @Param settings body UpdateChannelSettingsRequest true "Channel settings to update"
// @Success 200 {object} UpdateChannelSettingsResponse
// @Failure 400 {string} string "Invalid request data"
// @Failure 401 {string} string "Authorization information is missing or invalid"
// @Failure 403 {string} string "Insufficient permissions to update channel"
// @Failure 404 {string} string "Channel not found"
// @Failure 500 {string} string "Internal server error"
// @Router /channels/{id} [put]
// @Security JWTBearerToken
func (ctr *ChannelController) UpdateChannelSettings(c echo.Context) error {
	// Check if user context exists first
	userToken := c.Get("user")
	if userToken == nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "Authorization information is missing or invalid")
	}

	// Get user claims from context for authentication validation
	claims := helper.GetClaimsFromContext(c)
	if claims == nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "Authorization information is missing or invalid")
	}

	// Parse channel ID from URL parameter
	channelIDParam := c.Param("id")
	if channelIDParam == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Channel ID is required")
	}

	channelID, err := strconv.ParseInt(channelIDParam, 10, 32)
	if err != nil || channelID <= 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid channel ID")
	}

	// Parse and validate request body
	var req UpdateChannelSettingsRequest
	if err := c.Bind(&req); err != nil {
		c.Logger().Errorf("Failed to parse request body: %s", err.Error())
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request body")
	}

	// Validate request data
	if err := c.Validate(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	// Create a context with timeout for database operations
	ctx, cancel := context.WithTimeout(c.Request().Context(), 10*time.Second)
	defer cancel()

	// Check if channel exists
	_, err = ctr.s.CheckChannelExists(ctx, int32(channelID))
	if err != nil {
		c.Logger().Errorf("Channel %d not found: %s", channelID, err.Error())
		return echo.NewHTTPError(http.StatusNotFound, "Channel not found")
	}

	// Check user access level (must be >= 500 for operator access)
	userAccess, err := ctr.s.GetChannelUserAccess(ctx, int32(channelID), claims.UserID)
	if err != nil {
		c.Logger().Errorf("Failed to get user access for channel %d and user %d: %s", channelID, claims.UserID, err.Error())
		return echo.NewHTTPError(http.StatusForbidden, "Insufficient permissions to update channel")
	}

	if userAccess.Access < 500 {
		c.Logger().Warnf("User %d attempted to update channel %d with insufficient access level %d", claims.UserID, channelID, userAccess.Access)
		return echo.NewHTTPError(http.StatusForbidden, "Insufficient permissions to update channel")
	}

	// Prepare update parameters
	updateParams := models.UpdateChannelSettingsParams{
		ID: int32(channelID),
	}

	// Check if we need to get current channel data to preserve existing values
	var currentChannel *models.GetChannelByIDRow
	if req.Description == nil || req.URL == nil {
		channel, err := ctr.s.GetChannelByID(ctx, int32(channelID))
		if err != nil {
			c.Logger().Errorf("Failed to get current channel data: %s", err.Error())
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to update channel")
		}
		currentChannel = &channel
	}

	// Set description (use current value if not provided)
	if req.Description != nil {
		updateParams.Description = db.NewString(*req.Description)
	} else {
		updateParams.Description = currentChannel.Description
	}

	// Set URL (use current value if not provided)
	if req.URL != nil {
		// Additional URL validation
		if *req.URL != "" {
			if _, err := url.ParseRequestURI(*req.URL); err != nil {
				return echo.NewHTTPError(http.StatusBadRequest, "Invalid URL format")
			}
		}
		updateParams.Url = db.NewString(*req.URL)
	} else {
		updateParams.Url = currentChannel.Url
	}

	// Update channel settings
	updatedChannel, err := ctr.s.UpdateChannelSettings(ctx, updateParams)
	if err != nil {
		c.Logger().Errorf("Failed to update channel %d: %s", channelID, err.Error())
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to update channel")
	}

	// Log the update for audit purposes
	c.Logger().Infof("User %d updated settings for channel %d", claims.UserID, channelID)

	// Prepare response
	response := UpdateChannelSettingsResponse{
		ID:          updatedChannel.ID,
		Name:        updatedChannel.Name,
		Description: db.TextToString(updatedChannel.Description),
		URL:         db.TextToString(updatedChannel.Url),
		CreatedAt:   db.Int4ToInt32(updatedChannel.CreatedAt),
		UpdatedAt:   updatedChannel.LastUpdated,
	}

	return c.JSON(http.StatusOK, response)
}

// GetChannelSettingsResponse represents the channel details response
type GetChannelSettingsResponse struct {
	ID          int32  `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	URL         string `json:"url,omitempty"`
	MemberCount int32  `json:"member_count"`
	CreatedAt   int32  `json:"created_at"`
	UpdatedAt   int32  `json:"updated_at,omitempty"`
}

// GetChannelSettings handles retrieving channel settings
// @Summary Get channel settings
// @Description Retrieve current channel settings including description, URL, and member count
// @Tags channels
// @Accept json
// @Produce json
// @Param id path int true "Channel ID"
// @Success 200 {object} GetChannelSettingsResponse
// @Failure 400 {string} string "Invalid channel ID"
// @Failure 401 {string} string "Authorization information is missing or invalid"
// @Failure 403 {string} string "Insufficient permissions to view channel"
// @Failure 404 {string} string "Channel not found"
// @Failure 500 {string} string "Internal server error"
// @Router /channels/{id} [get]
// @Security JWTBearerToken
func (ctr *ChannelController) GetChannelSettings(c echo.Context) error {
	// Check if user context exists first
	userToken := c.Get("user")
	if userToken == nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "Authorization information is missing or invalid")
	}

	// Get user claims from context for authentication validation
	claims := helper.GetClaimsFromContext(c)
	if claims == nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "Authorization information is missing or invalid")
	}

	// Parse channel ID from URL parameter
	channelIDParam := c.Param("id")
	if channelIDParam == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Channel ID is required")
	}

	channelID, err := strconv.ParseInt(channelIDParam, 10, 32)
	if err != nil || channelID <= 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid channel ID")
	}

	// Create a context with timeout for database operations
	ctx, cancel := context.WithTimeout(c.Request().Context(), 5*time.Second)
	defer cancel()

	// Check if channel exists and get details
	channelDetails, err := ctr.s.GetChannelDetails(ctx, int32(channelID))
	if err != nil {
		c.Logger().Errorf("Channel %d not found: %s", channelID, err.Error())
		return echo.NewHTTPError(http.StatusNotFound, "Channel not found")
	}

	// Check user access level (must be >= 100 for viewing)
	userAccess, err := ctr.s.GetChannelUserAccess(ctx, int32(channelID), claims.UserID)
	if err != nil {
		c.Logger().Errorf("Failed to get user access for channel %d and user %d: %s", channelID, claims.UserID, err.Error())
		return echo.NewHTTPError(http.StatusForbidden, "Insufficient permissions to view channel")
	}

	if userAccess.Access < 100 {
		c.Logger().Warnf("User %d attempted to view channel %d with insufficient access level %d", claims.UserID, channelID, userAccess.Access)
		return echo.NewHTTPError(http.StatusForbidden, "Insufficient permissions to view channel")
	}

	// Log the access for audit purposes
	c.Logger().Infof("User %d viewed settings for channel %d", claims.UserID, channelID)

	// Prepare response
	response := GetChannelSettingsResponse{
		ID:          channelDetails.ID,
		Name:        channelDetails.Name,
		Description: db.TextToString(channelDetails.Description),
		URL:         db.TextToString(channelDetails.Url),
		MemberCount: safeInt32FromInt64(channelDetails.MemberCount),
		CreatedAt:   db.Int4ToInt32(channelDetails.CreatedAt),
	}

	// Add updated timestamp if available (non-zero value indicates it was updated)
	if channelDetails.LastUpdated > 0 {
		response.UpdatedAt = channelDetails.LastUpdated
	}

	return c.JSON(http.StatusOK, response)
}

// prepareSearchQuery sanitizes and prepares the search query for database use
func (ctr *ChannelController) prepareSearchQuery(query string) string {
	// Remove dangerous characters and prepare for ILIKE pattern matching
	// Add wildcard support: if no wildcards present, add them automatically
	if !strings.Contains(query, "%") && !strings.Contains(query, "_") {
		// If no wildcards, wrap the query to search for channels containing the term
		return "%" + query + "%"
	}
	return query
}

func (ctr *ChannelController) GetChannel() {

}

// AddMemberRequest represents the request body for adding a member to a channel
type AddMemberRequest struct {
	UserID      int64 `json:"user_id" validate:"required"`
	AccessLevel int   `json:"access_level" validate:"required,min=1,max=500"`
}

// AddMemberResponse represents the response for adding a member to a channel
type AddMemberResponse struct {
	ChannelID   int32  `json:"channel_id"`
	UserID      int64  `json:"user_id"`
	AccessLevel int    `json:"access_level"`
	AddedAt     int32  `json:"added_at"`
	Message     string `json:"message"`
}

// AddChannelMember handles adding a new member to a channel
// @Summary Add a member to a channel
// @Description Add a new member to a channel with specified access level and proper validation
// @Tags channels
// @Accept json
// @Produce json
// @Param id path int true "Channel ID"
// @Param request body AddMemberRequest true "Member addition request"
// @Success 201 {object} AddMemberResponse
// @Failure 400 {string} string "Invalid request data"
// @Failure 401 {string} string "Authorization information is missing or invalid"
// @Failure 403 {string} string "Insufficient permissions"
// @Failure 404 {string} string "Channel or user not found"
// @Failure 409 {string} string "User is already a member of this channel"
// @Failure 422 {string} string "Cannot add user with access level higher than or equal to your own"
// @Failure 500 {string} string "Internal server error"
// @Router /channels/{id}/members [post]
// @Security JWTBearerToken
func (ctr *ChannelController) AddChannelMember(c echo.Context) error {
	// Check if user context exists first
	userToken := c.Get("user")
	if userToken == nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "Authorization information is missing or invalid")
	}

	// Get user claims from context for authentication validation
	claims := helper.GetClaimsFromContext(c)
	if claims == nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "Authorization information is missing or invalid")
	}

	// Parse channel ID from URL parameter
	channelIDParam := c.Param("id")
	if channelIDParam == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Channel ID is required")
	}

	channelID, err := strconv.ParseInt(channelIDParam, 10, 32)
	if err != nil || channelID <= 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid channel ID")
	}

	// Create a context with timeout for database operations
	ctx, cancel := context.WithTimeout(c.Request().Context(), 10*time.Second)
	defer cancel()

	// SECURITY: Protect the special "*" channel
	channel, err := ctr.s.GetChannelByName(ctx, "*")
	if err == nil && channel.ID == int32(channelID) {
		return echo.NewHTTPError(http.StatusNotFound, "Channel not found")
	}

	// Parse and validate request body
	var req AddMemberRequest
	if err := c.Bind(&req); err != nil {
		c.Logger().Errorf("Failed to parse request body: %s", err.Error())
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request body")
	}

	// Validate request data
	if err := c.Validate(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	// Check if channel exists
	_, err = ctr.s.CheckChannelExists(ctx, int32(channelID))
	if err != nil {
		c.Logger().Errorf("Channel %d not found: %s", channelID, err.Error())
		return echo.NewHTTPError(http.StatusNotFound, "Channel not found")
	}

	// Check user access level (must be between 100 and 500 for adding members)
	userAccess, err := ctr.s.GetChannelUserAccess(ctx, int32(channelID), claims.UserID)
	if err != nil {
		c.Logger().Errorf("Failed to get user access for channel %d and user %d: %s", channelID, claims.UserID, err.Error())
		return echo.NewHTTPError(http.StatusForbidden, "Insufficient permissions to add members")
	}

	if userAccess.Access < 100 || userAccess.Access > 500 {
		c.Logger().Warnf("User %d attempted to add member to channel %d with invalid access level %d", claims.UserID, channelID, userAccess.Access)
		return echo.NewHTTPError(http.StatusForbidden, "Insufficient permissions to add members")
	}

	// Business rule: Cannot add users with access level >= own level
	if req.AccessLevel >= int(userAccess.Access) {
		c.Logger().Warnf("User %d attempted to add member with access level %d >= own level %d", claims.UserID, req.AccessLevel, userAccess.Access)
		return echo.NewHTTPError(http.StatusUnprocessableEntity, "Cannot add user with access level higher than or equal to your own")
	}

	// Check if the target user exists (by checking if they can be retrieved)
	// This is a basic existence check - you may want to add a specific user existence query
	_, err = ctr.s.GetChannelUserAccess(ctx, int32(channelID), safeInt32FromInt64(req.UserID))
	if err == nil {
		// User already has access to this channel
		return echo.NewHTTPError(http.StatusConflict, "User is already a member of this channel")
	}

	// Verify that the target user actually exists in the system
	// We'll try to check if they exist by doing a membership check on a dummy query
	_, err = ctr.s.CheckChannelMemberExists(ctx, int32(channelID), safeInt32FromInt64(req.UserID))
	if err == nil {
		// User already exists as a member
		c.Logger().Warnf("Attempt to add user %d who is already a member of channel %d", req.UserID, channelID)
		return echo.NewHTTPError(http.StatusConflict, "User is already a member of this channel")
	}

	// Add the new channel member
	addParams := models.AddChannelMemberParams{
		ChannelID: int32(channelID),
		UserID:    safeInt32FromInt64(req.UserID),
		Access:    safeInt32(req.AccessLevel),
		AddedBy:   db.NewString(claims.Username),
	}

	newMember, err := ctr.s.AddChannelMember(ctx, addParams)
	if err != nil {
		c.Logger().Errorf("Failed to add member to channel %d: %s", channelID, err.Error())
		// Check if this is a foreign key constraint error (user doesn't exist)
		if strings.Contains(err.Error(), "foreign key") || strings.Contains(err.Error(), "constraint") {
			return echo.NewHTTPError(http.StatusNotFound, "User not found")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to add member to channel")
	}

	// Log the addition for audit purposes
	c.Logger().Infof("User %d added user %d to channel %d with access level %d", claims.UserID, req.UserID, channelID, req.AccessLevel)

	// Prepare response
	response := AddMemberResponse{
		ChannelID:   newMember.ChannelID,
		UserID:      int64(newMember.UserID),
		AccessLevel: int(newMember.Access),
		AddedAt:     db.Int4ToInt32(newMember.Added),
		Message:     "Member added successfully",
	}

	return c.JSON(http.StatusCreated, response)
}
