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

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/labstack/echo/v4"
	"github.com/undernetirc/cservice-api/db"
	apierrors "github.com/undernetirc/cservice-api/internal/errors"
	"github.com/undernetirc/cservice-api/internal/helper"
	"github.com/undernetirc/cservice-api/internal/tracing"
	"github.com/undernetirc/cservice-api/models"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

type ChannelController struct {
	s    models.ServiceInterface
	pool PoolInterface
}

func NewChannelController(s models.ServiceInterface, pool PoolInterface) *ChannelController {
	return &ChannelController{s: s, pool: pool}
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
	logger := helper.GetRequestLogger(c)

	userToken := c.Get("user")
	if userToken == nil {
		return apierrors.HandleUnauthorizedError(c, "Authorization information is missing or invalid")
	}

	claims := helper.GetClaimsFromContext(c)
	if claims == nil {
		return apierrors.HandleUnauthorizedError(c, "Authorization information is missing or invalid")
	}

	req := &SearchChannelsRequest{
		Limit:  20, // Default limit
		Offset: 0,  // Default offset
	}

	// Manually parse query parameters with error handling
	queryParam := c.QueryParam("q")
	if queryParam == "" {
		return apierrors.HandleBadRequestError(c, "Search query parameter 'q' is required")
	}
	req.Query = queryParam

	if limitParam := c.QueryParam("limit"); limitParam != "" {
		limit, err := strconv.Atoi(limitParam)
		if err != nil {
			return apierrors.HandleBadRequestError(c, "Invalid limit parameter: must be a number")
		}
		if limit < 1 || limit > 100 {
			return apierrors.HandleBadRequestError(c, "Invalid limit parameter: must be between 1 and 100")
		}
		req.Limit = limit
	}

	if offsetParam := c.QueryParam("offset"); offsetParam != "" {
		offset, err := strconv.Atoi(offsetParam)
		if err != nil {
			return apierrors.HandleBadRequestError(c, "Invalid offset parameter: must be a number")
		}
		if offset < 0 {
			return apierrors.HandleBadRequestError(c, "Invalid offset parameter: must be 0 or greater")
		}
		req.Offset = offset
	}

	if err := c.Validate(req); err != nil {
		return apierrors.HandleValidationError(c, err)
	}

	searchQuery := ctr.prepareSearchQuery(req.Query)

	// Log the search request for audit purposes
	logger.Info("User searching channels",
		"userID", claims.UserID,
		"query", req.Query,
		"preparedQuery", searchQuery,
		"limit", req.Limit,
		"offset", req.Offset)

	ctx, cancel := context.WithTimeout(c.Request().Context(), 5*time.Second)
	defer cancel()

	// Start tracing for the channel search operation
	resultCount, err := tracing.TraceChannelSearch(ctx, claims.UserID, req.Query, func(ctx context.Context) (int, error) {
		// Trace the count query stage
		var totalCount int64
		err := tracing.TraceOperation(ctx, "get_search_count", func(ctx context.Context) error {
			var err error
			totalCount, err = ctr.s.SearchChannelsCount(ctx, searchQuery)
			if err != nil {
				logger.Error("Failed to get channel search count",
					"userID", claims.UserID,
					"query", searchQuery,
					"error", err.Error())
				return apierrors.HandleDatabaseError(c, err)
			}
			return nil
		})
		if err != nil {
			return 0, err
		}

		// Trace the search query stage
		var channelRows []models.SearchChannelsRow
		err = tracing.TraceOperation(ctx, "execute_search", func(ctx context.Context) error {
			span := trace.SpanFromContext(ctx)
			searchParams := models.SearchChannelsParams{
				Name:   searchQuery,
				Limit:  helper.SafeInt32(req.Limit),
				Offset: helper.SafeInt32(req.Offset),
			}

			span.SetAttributes(
				attribute.String("search.original_query", req.Query),
				attribute.String("search.prepared_query", searchQuery),
				attribute.Int("search.limit", req.Limit),
				attribute.Int("search.offset", req.Offset),
				attribute.Int64("search.user_id", int64(claims.UserID)),
				attribute.String("search.user_agent", c.Request().UserAgent()),
				attribute.String("search.client_ip", c.RealIP()),
				attribute.Bool("search.has_wildcards", strings.Contains(req.Query, "*") || strings.Contains(req.Query, "?")),
				attribute.Int("search.query_length", len(req.Query)),
			)

			var err error
			channelRows, err = ctr.s.SearchChannels(ctx, searchParams)
			if err != nil {
				logger.Error("Failed to search channels",
					"userID", claims.UserID,
					"searchParams", searchParams,
					"error", err.Error())
				span.SetAttributes(
					attribute.Bool("search.query_success", false),
					attribute.String("search.database_error", err.Error()),
				)
				return apierrors.HandleDatabaseError(c, err)
			}

			span.SetAttributes(
				attribute.Bool("search.query_success", true),
				attribute.Int("search.raw_result_count", len(channelRows)),
			)
			return nil
		})
		if err != nil {
			return 0, err
		}

		// Trace the result formatting stage
		err = tracing.TraceOperation(ctx, "format_results", func(ctx context.Context) error {
			span := trace.SpanFromContext(ctx)

			// Convert database rows to response format
			channels := make([]ChannelSearchResult, len(channelRows))
			channelsWithDescription := 0
			channelsWithURL := 0
			totalMemberCount := int64(0)

			for i, row := range channelRows {
				channels[i] = ChannelSearchResult{
					ID:          row.ID,
					Name:        row.Name,
					Description: db.TextToString(row.Description),
					URL:         db.TextToString(row.Url),
					MemberCount: helper.SafeInt32FromInt64(row.MemberCount),
					CreatedAt:   db.Int4ToInt32(row.CreatedAt),
				}

				if channels[i].Description != "" {
					channelsWithDescription++
				}
				if channels[i].URL != "" {
					channelsWithURL++
				}
				totalMemberCount += row.MemberCount
			}

			// Calculate pagination info
			hasMore := int64(req.Offset+req.Limit) < totalCount

			span.SetAttributes(
				attribute.Int("results.formatted_count", len(channels)),
				attribute.Int("results.channels_with_description", channelsWithDescription),
				attribute.Int("results.channels_with_url", channelsWithURL),
				attribute.Int64("results.total_member_count", totalMemberCount),
				attribute.Int64("results.total_available", totalCount),
				attribute.Bool("results.has_more", hasMore),
				attribute.Float64("results.description_ratio", float64(channelsWithDescription)/float64(len(channels))),
				attribute.Float64("results.url_ratio", float64(channelsWithURL)/float64(len(channels))),
			)

			if len(channels) > 0 {
				span.SetAttributes(
					attribute.Float64("results.avg_member_count", float64(totalMemberCount)/float64(len(channels))),
				)
			}

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
		})
		if err != nil {
			return 0, err
		}

		return len(channelRows), nil
	})

	if err != nil {
		return err
	}

	// Log successful search completion
	logger.Info("Channel search completed successfully",
		"userID", claims.UserID,
		"query", req.Query,
		"resultCount", resultCount)

	return nil
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
	logger := helper.GetRequestLogger(c)

	// Check if user context exists first
	userToken := c.Get("user")
	if userToken == nil {
		return apierrors.HandleUnauthorizedError(c, "Authorization information is missing or invalid")
	}

	// Get user claims from context for authentication validation
	claims := helper.GetClaimsFromContext(c)
	if claims == nil {
		return apierrors.HandleUnauthorizedError(c, "Authorization information is missing or invalid")
	}

	// Parse channel ID from URL parameter
	channelIDParam := c.Param("id")
	if channelIDParam == "" {
		return apierrors.HandleBadRequestError(c, "Channel ID is required")
	}

	channelID, err := strconv.ParseInt(channelIDParam, 10, 32)
	if err != nil || channelID <= 0 {
		return apierrors.HandleBadRequestError(c, "Invalid channel ID")
	}

	// Parse and validate request body
	var req UpdateChannelSettingsRequest
	if err := c.Bind(&req); err != nil {
		logger.Error("Failed to parse request body",
			"userID", claims.UserID,
			"channelID", channelID,
			"error", err.Error())
		return apierrors.HandleBadRequestError(c, "Invalid request body")
	}

	// Validate request data
	if err := c.Validate(&req); err != nil {
		return apierrors.HandleValidationError(c, err)
	}

	// Create a context with timeout for database operations
	ctx, cancel := context.WithTimeout(c.Request().Context(), 10*time.Second)
	defer cancel()

	// Check if channel exists
	_, err = ctr.s.CheckChannelExists(ctx, int32(channelID))
	if err != nil {
		logger.Error("Channel not found",
			"userID", claims.UserID,
			"channelID", channelID,
			"error", err.Error())
		return apierrors.HandleNotFoundError(c, "Channel")
	}

	// Check user access level (must be >= 450 for updating channel settings, per CService documentation)
	userAccess, err := ctr.s.GetChannelUserAccess(ctx, int32(channelID), claims.UserID)
	if err != nil {
		logger.Error("Failed to get user access for channel",
			"userID", claims.UserID,
			"channelID", channelID,
			"error", err.Error())
		return apierrors.HandleForbiddenError(c, "Insufficient permissions to update channel")
	}

	if userAccess.Access < 450 {
		logger.Warn("User attempted to update channel with insufficient access",
			"userID", claims.UserID,
			"channelID", channelID,
			"accessLevel", userAccess.Access)
		return apierrors.HandleForbiddenError(c, "Insufficient permissions to update channel")
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
			logger.Error("Failed to get current channel data",
				"userID", claims.UserID,
				"channelID", channelID,
				"error", err.Error())
			return apierrors.HandleDatabaseError(c, err)
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
				return apierrors.HandleBadRequestError(c, "Invalid URL format")
			}
		}
		updateParams.Url = db.NewString(*req.URL)
	} else {
		updateParams.Url = currentChannel.Url
	}

	// Update channel settings
	updatedChannel, err := ctr.s.UpdateChannelSettings(ctx, updateParams)
	if err != nil {
		logger.Error("Failed to update channel",
			"userID", claims.UserID,
			"channelID", channelID,
			"error", err.Error())
		return apierrors.HandleDatabaseError(c, err)
	}

	// Log the update for audit purposes
	logger.Info("User updated channel settings",
		"userID", claims.UserID,
		"channelID", channelID)

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
	logger := helper.GetRequestLogger(c)

	// Check if user context exists first
	userToken := c.Get("user")
	if userToken == nil {
		return apierrors.HandleUnauthorizedError(c, "Authorization information is missing or invalid")
	}

	// Get user claims from context for authentication validation
	claims := helper.GetClaimsFromContext(c)
	if claims == nil {
		return apierrors.HandleUnauthorizedError(c, "Authorization information is missing or invalid")
	}

	// Parse channel ID from URL parameter
	channelIDParam := c.Param("id")
	if channelIDParam == "" {
		return apierrors.HandleBadRequestError(c, "Channel ID is required")
	}

	channelID, err := strconv.ParseInt(channelIDParam, 10, 32)
	if err != nil || channelID <= 0 {
		return apierrors.HandleBadRequestError(c, "Invalid channel ID")
	}

	// Create a context with timeout for database operations
	ctx, cancel := context.WithTimeout(c.Request().Context(), 5*time.Second)
	defer cancel()

	// Check if channel exists and get details
	channelDetails, err := ctr.s.GetChannelDetails(ctx, int32(channelID))
	if err != nil {
		logger.Error("Channel not found",
			"userID", claims.UserID,
			"channelID", channelID,
			"error", err.Error())
		return apierrors.HandleNotFoundError(c, "Channel")
	}

	// Check user access level (must be >= 100 for viewing)
	userAccess, err := ctr.s.GetChannelUserAccess(ctx, int32(channelID), claims.UserID)
	if err != nil {
		logger.Error("Failed to get user access for channel",
			"userID", claims.UserID,
			"channelID", channelID,
			"error", err.Error())
		return apierrors.HandleForbiddenError(c, "Insufficient permissions to view channel")
	}

	if userAccess.Access < 100 {
		logger.Warn("User attempted to view channel with insufficient access",
			"userID", claims.UserID,
			"channelID", channelID,
			"accessLevel", userAccess.Access)
		return apierrors.HandleForbiddenError(c, "Insufficient permissions to view channel")
	}

	// Log the access for audit purposes
	logger.Info("User viewed channel settings",
		"userID", claims.UserID,
		"channelID", channelID)

	// Prepare response
	response := GetChannelSettingsResponse{
		ID:          channelDetails.ID,
		Name:        channelDetails.Name,
		Description: db.TextToString(channelDetails.Description),
		URL:         db.TextToString(channelDetails.Url),
		MemberCount: helper.SafeInt32FromInt64(channelDetails.MemberCount),
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
	AccessLevel int   `json:"access_level" validate:"required,min=1,max=499"`
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
	logger := helper.GetRequestLogger(c)

	// Check if user context exists first
	userToken := c.Get("user")
	if userToken == nil {
		return apierrors.HandleUnauthorizedError(c, "Authorization information is missing or invalid")
	}

	// Get user claims from context for authentication validation
	claims := helper.GetClaimsFromContext(c)
	if claims == nil {
		return apierrors.HandleUnauthorizedError(c, "Authorization information is missing or invalid")
	}

	// Parse channel ID from URL parameter
	channelIDParam := c.Param("id")
	if channelIDParam == "" {
		return apierrors.HandleBadRequestError(c, "Channel ID is required")
	}

	channelID, err := strconv.ParseInt(channelIDParam, 10, 32)
	if err != nil || channelID <= 0 {
		return apierrors.HandleBadRequestError(c, "Invalid channel ID")
	}

	// Create a context with timeout for database operations
	ctx, cancel := context.WithTimeout(c.Request().Context(), 10*time.Second)
	defer cancel()

	// SECURITY: Protect the special "*" channel
	channel, err := ctr.s.GetChannelByName(ctx, "*")
	if err == nil && channel.ID == int32(channelID) {
		return apierrors.HandleNotFoundError(c, "Channel")
	}

	// Parse and validate request body
	var req AddMemberRequest
	if err := c.Bind(&req); err != nil {
		logger.Error("Failed to parse request body",
			"userID", claims.UserID,
			"channelID", channelID,
			"error", err.Error())
		return apierrors.HandleBadRequestError(c, "Invalid request body")
	}

	// Validate request data
	if err := c.Validate(&req); err != nil {
		return apierrors.HandleValidationError(c, err)
	}

	// Check if channel exists
	_, err = ctr.s.CheckChannelExists(ctx, int32(channelID))
	if err != nil {
		logger.Error("Channel not found",
			"userID", claims.UserID,
			"channelID", channelID,
			"error", err.Error())
		return apierrors.HandleNotFoundError(c, "Channel")
	}

	// Check user access level (must be >= 400 for adding members, per CService documentation)
	userAccess, err := ctr.s.GetChannelUserAccess(ctx, int32(channelID), claims.UserID)
	if err != nil {
		logger.Error("Failed to get user access for channel",
			"userID", claims.UserID,
			"channelID", channelID,
			"error", err.Error())
		return apierrors.HandleForbiddenError(c, "Insufficient permissions to add members")
	}

	if userAccess.Access < 400 {
		logger.Warn("User attempted to add member with insufficient access level",
			"userID", claims.UserID,
			"channelID", channelID,
			"accessLevel", userAccess.Access)
		return apierrors.HandleForbiddenError(c, "Insufficient permissions to add members")
	}

	// Business rule: Cannot add users with access level >= own level
	if req.AccessLevel >= int(userAccess.Access) {
		logger.Warn("User attempted to add member with access level >= own level",
			"userID", claims.UserID,
			"requestedLevel", req.AccessLevel,
			"userLevel", userAccess.Access)
		return apierrors.HandleUnprocessableEntityError(c, "Cannot add user with access level higher than or equal to your own")
	}

	// Check if the target user exists (by checking if they can be retrieved)
	// This is a basic existence check - you may want to add a specific user existence query
	_, err = ctr.s.GetChannelUserAccess(ctx, int32(channelID), helper.SafeInt32FromInt64(req.UserID))
	if err == nil {
		// User already has access to this channel
		return apierrors.HandleConflictError(c, "User is already a member of this channel")
	}

	// Verify that the target user actually exists in the system
	// We'll try to check if they exist by doing a membership check on a dummy query
	_, err = ctr.s.CheckChannelMemberExists(ctx, int32(channelID), helper.SafeInt32FromInt64(req.UserID))
	if err == nil {
		// User already exists as a member
		logger.Warn("Attempt to add user who is already a member",
			"userID", claims.UserID,
			"targetUserID", req.UserID,
			"channelID", channelID)
		return apierrors.HandleConflictError(c, "User is already a member of this channel")
	}

	// Add the new channel member
	addParams := models.AddChannelMemberParams{
		ChannelID: int32(channelID),
		UserID:    helper.SafeInt32FromInt64(req.UserID),
		Access:    helper.SafeInt32(req.AccessLevel),
		AddedBy:   db.NewString(claims.Username),
	}

	newMember, err := ctr.s.AddChannelMember(ctx, addParams)
	if err != nil {
		logger.Error("Failed to add member to channel",
			"userID", claims.UserID,
			"targetUserID", req.UserID,
			"channelID", channelID,
			"error", err.Error())

		// Check if this is a foreign key constraint error (user doesn't exist)
		if strings.Contains(err.Error(), "foreign key") || strings.Contains(err.Error(), "constraint") {
			return apierrors.HandleNotFoundError(c, "User")
		}
		return apierrors.HandleDatabaseError(c, err)
	}

	// Log the addition for audit purposes
	logger.Info("User added member to channel",
		"userID", claims.UserID,
		"targetUserID", req.UserID,
		"channelID", channelID,
		"accessLevel", req.AccessLevel)

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

// RemoveMemberRequest represents the request body for removing a member from a channel
type RemoveMemberRequest struct {
	UserID int64 `json:"user_id" validate:"required"`
}

// RemoveMemberResponse represents the response for removing a member from a channel
type RemoveMemberResponse struct {
	ChannelID int32  `json:"channel_id"`
	UserID    int64  `json:"user_id"`
	RemovedAt int32  `json:"removed_at"`
	Message   string `json:"message"`
}

// RemoveChannelMember handles removing a member from a channel
// @Summary Remove a member from a channel
// @Description Remove a member from a channel with proper validation and access control
// @Tags channels
// @Accept json
// @Produce json
// @Param id path int true "Channel ID"
// @Param request body RemoveMemberRequest true "Member removal request"
// @Success 200 {object} RemoveMemberResponse
// @Failure 400 {string} string "Invalid request data"
// @Failure 401 {string} string "Authorization information is missing or invalid"
// @Failure 403 {string} string "Insufficient permissions"
// @Failure 404 {string} string "Channel or user not found"
// @Failure 409 {string} string "Cannot remove the last channel owner"
// @Failure 422 {string} string "Cannot remove user with access level higher than or equal to your own"
// @Failure 500 {string} string "Internal server error"
// @Router /channels/{id}/members [delete]
// @Security JWTBearerToken
func (ctr *ChannelController) RemoveChannelMember(c echo.Context) error {
	logger := helper.GetRequestLogger(c)

	// Check if user context exists first
	userToken := c.Get("user")
	if userToken == nil {
		return apierrors.HandleUnauthorizedError(c, "Authorization information is missing or invalid")
	}

	// Get user claims from context for authentication validation
	claims := helper.GetClaimsFromContext(c)
	if claims == nil {
		return apierrors.HandleUnauthorizedError(c, "Authorization information is missing or invalid")
	}

	// Parse channel ID from URL parameter
	channelIDParam := c.Param("id")
	if channelIDParam == "" {
		return apierrors.HandleBadRequestError(c, "Channel ID is required")
	}

	channelID, err := strconv.ParseInt(channelIDParam, 10, 32)
	if err != nil || channelID <= 0 {
		return apierrors.HandleBadRequestError(c, "Invalid channel ID")
	}

	// Create a context with timeout for database operations
	ctx, cancel := context.WithTimeout(c.Request().Context(), 10*time.Second)
	defer cancel()

	// SECURITY: Protect the special "*" channel
	channel, err := ctr.s.GetChannelByName(ctx, "*")
	if err == nil && channel.ID == int32(channelID) {
		return apierrors.HandleNotFoundError(c, "Channel")
	}

	// Parse and validate request body
	var req RemoveMemberRequest
	if err := c.Bind(&req); err != nil {
		logger.Error("Failed to parse request body",
			"userID", claims.UserID,
			"channelID", channelID,
			"error", err.Error())
		return apierrors.HandleBadRequestError(c, "Invalid request body")
	}

	// Validate request data
	if err := c.Validate(&req); err != nil {
		return apierrors.HandleValidationError(c, err)
	}

	// Check if channel exists
	_, err = ctr.s.CheckChannelExists(ctx, int32(channelID))
	if err != nil {
		logger.Error("Channel not found",
			"userID", claims.UserID,
			"channelID", channelID,
			"error", err.Error())
		return apierrors.HandleNotFoundError(c, "Channel")
	}

	// Check if this is self-removal first to determine access requirements
	isSelfRemoval := claims.UserID == helper.SafeInt32FromInt64(req.UserID)

	// Get current user access level
	userAccess, err := ctr.s.GetChannelUserAccess(ctx, int32(channelID), claims.UserID)
	if err != nil {
		logger.Error("Failed to get user access for channel",
			"userID", claims.UserID,
			"channelID", channelID,
			"error", err.Error())
		return apierrors.HandleForbiddenError(c, "Insufficient permissions to remove members")
	}

	// Access level requirements:
	// - Self-removal: >= 1 (per CService documentation)
	// - Removing others: >= 400 (per CService documentation)
	var requiredLevel int32 = 400
	if isSelfRemoval {
		requiredLevel = 1
	}

	if userAccess.Access < requiredLevel {
		action := "remove member"
		if isSelfRemoval {
			action = "remove yourself"
		}
		logger.Warn("User attempted to "+action+" with insufficient access level",
			"userID", claims.UserID,
			"channelID", channelID,
			"accessLevel", userAccess.Access,
			"requiredLevel", requiredLevel)
		return apierrors.HandleForbiddenError(c, "Insufficient permissions to remove members")
	}

	// Check if target user exists in the channel
	targetUserAccess, err := ctr.s.GetChannelUserAccess(ctx, int32(channelID), helper.SafeInt32FromInt64(req.UserID))
	if err != nil {
		logger.Error("Target user not found in channel",
			"userID", claims.UserID,
			"targetUserID", req.UserID,
			"channelID", channelID,
			"error", err.Error())

		logger.Info("Resource not found",
			"path", c.Request().URL.Path,
			"method", c.Request().Method,
			"resource", "User is not a member of this channel")

		return c.JSON(http.StatusNotFound, apierrors.NewErrorResponse(
			apierrors.ErrCodeNotFound,
			"User is not a member of this channel",
			nil,
		))
	}

	// Now handle the removal logic based on whether it's self-removal or not

	if isSelfRemoval {
		// Self-removal: Users can remove themselves unless they have level 500 access (owner)
		if userAccess.Access >= 500 {
			// Check if this is the last owner
			ownerCount, err := ctr.s.CountChannelOwners(ctx, int32(channelID))
			if err != nil {
				logger.Error("Failed to count channel owners",
					"userID", claims.UserID,
					"channelID", channelID,
					"error", err.Error())
				return apierrors.HandleInternalError(c, err, "Failed to process removal request")
			}

			if ownerCount <= 1 {
				logger.Warn("User attempted to remove themselves as last owner",
					"userID", claims.UserID,
					"channelID", channelID)
				return apierrors.HandleConflictError(c, "Cannot remove the last channel owner")
			}
		}
	} else {
		// Removing another user: Cannot remove users with equal or higher access level
		if targetUserAccess.Access >= userAccess.Access {
			logger.Warn("User attempted to remove user with access level >= own level",
				"userID", claims.UserID,
				"targetUserID", req.UserID,
				"targetLevel", targetUserAccess.Access,
				"userLevel", userAccess.Access)
			return apierrors.HandleUnprocessableEntityError(c, "Cannot remove user with access level higher than or equal to your own")
		}

		// Additional check: If target user is an owner (level 500), ensure they're not the last owner
		if targetUserAccess.Access >= 500 {
			ownerCount, err := ctr.s.CountChannelOwners(ctx, int32(channelID))
			if err != nil {
				logger.Error("Failed to count channel owners",
					"userID", claims.UserID,
					"channelID", channelID,
					"error", err.Error())
				return apierrors.HandleInternalError(c, err, "Failed to process removal request")
			}

			if ownerCount <= 1 {
				logger.Warn("User attempted to remove the last owner",
					"userID", claims.UserID,
					"targetUserID", req.UserID,
					"channelID", channelID)
				return apierrors.HandleConflictError(c, "Cannot remove the last channel owner")
			}
		}
	}

	// Remove the channel member
	removeParams := models.RemoveChannelMemberParams{
		ChannelID:   int32(channelID),
		UserID:      helper.SafeInt32FromInt64(req.UserID),
		LastModifBy: db.NewString(claims.Username),
	}

	removedMember, err := ctr.s.RemoveChannelMember(ctx, removeParams)
	if err != nil {
		logger.Error("Failed to remove member from channel",
			"userID", claims.UserID,
			"targetUserID", req.UserID,
			"channelID", channelID,
			"error", err.Error())
		return apierrors.HandleDatabaseError(c, err)
	}

	// Log the removal for audit purposes
	if isSelfRemoval {
		logger.Info("User removed themselves from channel",
			"userID", claims.UserID,
			"channelID", channelID)
	} else {
		logger.Info("User removed member from channel",
			"userID", claims.UserID,
			"targetUserID", req.UserID,
			"channelID", channelID)
	}

	// Prepare response
	response := RemoveMemberResponse{
		ChannelID: removedMember.ChannelID,
		UserID:    int64(removedMember.UserID),
		RemovedAt: db.Int4ToInt32(removedMember.LastModif),
		Message:   "Member removed successfully",
	}

	return c.JSON(http.StatusOK, response)
}

// Channel Registration Types and Handler

// ChannelRegistrationRequest represents the incoming JSON payload for channel registration
type ChannelRegistrationRequest struct {
	ChannelName string   `json:"channel_name" validate:"required,startswith=#,max=255"`
	Description string   `json:"description" validate:"required,max=300"`
	Supporters  []string `json:"supporters" validate:"required,min=1"`
}

// ChannelRegistrationData represents the data portion of a successful channel registration application response
type ChannelRegistrationData struct {
	ChannelName   string    `json:"channel_name"`
	Status        string    `json:"status"`         // e.g., "pending", "under_review"
	SubmittedAt   time.Time `json:"submitted_at"`   // When the application was submitted
	ApplicationID int64     `json:"application_id"` // ID of the pending registration application
}

// ChannelRegistrationResponse represents the success response for channel registration
type ChannelRegistrationResponse struct {
	Data   ChannelRegistrationData `json:"data"`
	Status string                  `json:"status"` // Always "success"
}

// RegisterChannel handles channel registration requests
// @Summary Submit a channel registration application
// @Description Submit a new IRC channel registration application with validation and business rule enforcement
// @Tags channels
// @Accept json
// @Produce json
// @Param request body ChannelRegistrationRequest true "Channel registration request"
// @Success 201 {object} ChannelRegistrationResponse
// @Failure 400 {object} errors.ErrorResponse "Invalid request data"
// @Failure 401 {object} errors.ErrorResponse "Authorization information is missing or invalid"
// @Failure 403 {object} errors.ErrorResponse "User is restricted from registering channels"
// @Failure 409 {object} errors.ErrorResponse "Channel name already exists or user has pending registration"
// @Failure 422 {object} errors.ErrorResponse "Validation failed"
// @Failure 429 {object} errors.ErrorResponse "Cooldown period active"
// @Failure 500 {object} errors.ErrorResponse "Internal server error"
// @Router /channels [post]
// @Security JWTBearerToken
func (ctr *ChannelController) RegisterChannel(c echo.Context) error {
	logger := helper.GetRequestLogger(c)

	userToken := c.Get("user")
	if userToken == nil {
		return apierrors.HandleUnauthorizedError(c, "Authorization information is missing or invalid")
	}

	claims := helper.GetClaimsFromContext(c)
	if claims == nil {
		return apierrors.HandleUnauthorizedError(c, "Authorization information is missing or invalid")
	}

	adminLevel := claims.Adm

	var req ChannelRegistrationRequest
	if err := c.Bind(&req); err != nil {
		logger.Error("Failed to parse channel registration request body",
			"userID", claims.UserID,
			"error", err.Error())
		return apierrors.HandleBadRequestError(c, "Invalid request body")
	}

	if err := c.Validate(&req); err != nil {
		logger.Warn("Request validation failed",
			"userID", claims.UserID,
			"channelName", req.ChannelName,
			"validationError", err.Error())
		return apierrors.HandleValidationError(c, err)
	}

	ctx, cancel := context.WithTimeout(c.Request().Context(), 30*time.Second)
	defer cancel()

	logger.Info("User attempting channel registration",
		"userID", claims.UserID,
		"username", claims.Username,
		"channelName", req.ChannelName,
		"supportersCount", len(req.Supporters),
		"adminLevel", adminLevel)

	validator := helper.NewChannelRegistrationValidator(ctr.s, helper.NewValidator())

	helperReq := &helper.ChannelRegistrationRequest{
		ChannelName: req.ChannelName,
		Description: req.Description,
		Supporters:  req.Supporters,
	}

	errorHandler := apierrors.NewChannelRegistrationErrorHandler()

	var allBypasses []helper.AdminBypassInfo
	if _, err := validator.ValidateChannelRegistrationWithAdminBypass(ctx, helperReq, claims.UserID, adminLevel); err != nil {
		if validationErr, ok := err.(*helper.ValidationError); ok {
			logger.Warn("Channel registration validation failed",
				"userID", claims.UserID,
				"channelName", req.ChannelName,
				"validationCode", validationErr.Code,
				"validationMessage", validationErr.Message)
		}
		return errorHandler.HandleValidationError(c, err)
	}

	if _, err := validator.ValidateUserNoregStatusWithAdminBypass(ctx, claims.UserID, adminLevel); err != nil {
		if validationErr, ok := err.(*helper.ValidationError); ok {
			logger.Warn("User restricted from channel registration",
				"userID", claims.UserID,
				"restrictionCode", validationErr.Code)
		}
		return errorHandler.HandleBusinessRuleError(c, err)
	}

	channelLimitBypasses, err := validator.ValidateUserChannelLimitsWithAdminBypass(ctx, claims.UserID, adminLevel)
	if err != nil {
		if validationErr, ok := err.(*helper.ValidationError); ok {
			logger.Warn("User exceeded channel limits",
				"userID", claims.UserID,
				"limitCode", validationErr.Code)
		}
		return errorHandler.HandleBusinessRuleError(c, err)
	}
	allBypasses = append(allBypasses, channelLimitBypasses...)

	pendingBypasses, err := validator.ValidatePendingRegistrationsWithAdminBypass(ctx, claims.UserID, adminLevel)
	if err != nil {
		if validationErr, ok := err.(*helper.ValidationError); ok {
			logger.Warn("User has pending registration",
				"userID", claims.UserID,
				"pendingCode", validationErr.Code)
		}
		return errorHandler.HandleBusinessRuleError(c, err)
	}
	allBypasses = append(allBypasses, pendingBypasses...)

	if _, err := validator.ValidateChannelNameAvailabilityWithAdminBypass(ctx, req.ChannelName, adminLevel); err != nil {
		if validationErr, ok := err.(*helper.ValidationError); ok {
			logger.Warn("Channel name not available",
				"userID", claims.UserID,
				"channelName", req.ChannelName,
				"availabilityCode", validationErr.Code)
		}
		return errorHandler.HandleBusinessRuleError(c, err)
	}

	if _, err := validator.ValidateUserIRCActivityWithAdminBypass(ctx, claims.UserID, adminLevel); err != nil {
		if validationErr, ok := err.(*helper.ValidationError); ok {
			logger.Warn("User does not meet IRC activity requirements",
				"userID", claims.UserID,
				"activityCode", validationErr.Code)
		}
		return errorHandler.HandleBusinessRuleError(c, err)
	}

	if len(allBypasses) > 0 {
		for _, bypass := range allBypasses {
			logger.Warn("Admin bypass applied during channel registration",
				"userID", bypass.UserID,
				"adminLevel", bypass.AdminLevel,
				"bypassType", bypass.BypassType,
				"details", bypass.Details,
				"channelName", req.ChannelName)
		}
	}

	tx, err := ctr.pool.Begin(ctx)
	if err != nil {
		logger.Error("Failed to start database transaction for channel registration",
			"userID", claims.UserID,
			"channelName", req.ChannelName,
			"error", err.Error())
		return apierrors.HandleDatabaseError(c, err)
	}

	defer func() {
		if rollbackErr := tx.Rollback(ctx); rollbackErr != nil {
			logger.Error("Failed to rollback channel registration transaction",
				"userID", claims.UserID,
				"channelName", req.ChannelName,
				"error", rollbackErr.Error())
		}
	}()

	qtx := ctr.s.WithTx(tx)

	// Create a temporary channel entry to get a channel ID
	// This is needed because the pending table references a channel_id
	tempChannelParams := models.CreateChannelParams{
		Name:        req.ChannelName,
		Flags:       0,
		Description: db.NewString(req.Description),
	}

	tempChannel, err := qtx.CreateChannel(ctx, tempChannelParams)
	if err != nil {
		logger.Error("Failed to create temporary channel entry in transaction",
			"userID", claims.UserID,
			"channelName", req.ChannelName,
			"error", err.Error())
		return apierrors.HandleDatabaseError(c, err)
	}

	pendingParams := models.CreatePendingChannelParams{
		ChannelID:   tempChannel.ID,
		ManagerID:   pgtype.Int4{Int32: claims.UserID, Valid: true},
		Managername: db.NewString(claims.Username),
		Description: db.NewString(req.Description),
	}

	pendingRegistration, err := qtx.CreatePendingChannel(ctx, pendingParams)
	if err != nil {
		logger.Error("Failed to create pending channel registration in transaction",
			"userID", claims.UserID,
			"channelName", req.ChannelName,
			"channelID", tempChannel.ID,
			"error", err.Error())
		return apierrors.HandleDatabaseError(c, err)
	}

	for _, supporterUsername := range req.Supporters {
		logger.Info("Processing supporter for pending registration",
			"userID", claims.UserID,
			"channelID", tempChannel.ID,
			"supporter", supporterUsername)

		supporterUser, err := qtx.GetUser(ctx, models.GetUserParams{
			Username: supporterUsername,
		})
		if err != nil {
			logger.Error("Failed to find supporter user in transaction",
				"userID", claims.UserID,
				"channelID", tempChannel.ID,
				"supporter", supporterUsername,
				"error", err.Error())
			return apierrors.HandleDatabaseError(c, err)
		}

		err = qtx.CreateChannelSupporter(ctx, tempChannel.ID, supporterUser.ID)
		if err != nil {
			logger.Error("Failed to create supporter entry in transaction",
				"userID", claims.UserID,
				"channelID", tempChannel.ID,
				"supporter", supporterUsername,
				"supporterUserID", supporterUser.ID,
				"error", err.Error())
			return apierrors.HandleDatabaseError(c, err)
		}

		logger.Info("Successfully created supporter entry",
			"userID", claims.UserID,
			"channelID", tempChannel.ID,
			"supporter", supporterUsername,
			"supporterUserID", supporterUser.ID)
	}

	if err := tx.Commit(ctx); err != nil {
		logger.Error("Failed to commit channel registration transaction",
			"userID", claims.UserID,
			"channelName", req.ChannelName,
			"channelID", tempChannel.ID,
			"error", err.Error())
		return apierrors.HandleDatabaseError(c, err)
	}

	logger.Info("Channel registration application created successfully",
		"userID", claims.UserID,
		"username", claims.Username,
		"channelName", req.ChannelName,
		"channelID", tempChannel.ID,
		"applicationID", pendingRegistration.ChannelID,
		"submittedAt", pendingRegistration.CreatedTs)

	response := ChannelRegistrationResponse{
		Data: ChannelRegistrationData{
			ChannelName:   req.ChannelName,
			Status:        "pending",
			SubmittedAt:   time.Unix(int64(pendingRegistration.CreatedTs), 0),
			ApplicationID: int64(pendingRegistration.ChannelID),
		},
		Status: "success",
	}

	return c.JSON(http.StatusCreated, response)
}
