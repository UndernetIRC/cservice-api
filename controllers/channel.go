// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package controllers

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/labstack/echo/v4"
	"github.com/undernetirc/cservice-api/db"
	"github.com/undernetirc/cservice-api/db/types/flags"
	"github.com/undernetirc/cservice-api/internal/channel"
	apierrors "github.com/undernetirc/cservice-api/internal/errors"
	"github.com/undernetirc/cservice-api/internal/helper"
	"github.com/undernetirc/cservice-api/internal/mail"
	"github.com/undernetirc/cservice-api/internal/tracing"
	"github.com/undernetirc/cservice-api/models"
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
	Query  string `query:"q"      validate:"required,min=1,max=100"`
	Limit  int    `query:"limit"  validate:"omitempty,min=1,max=100"`
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

	var totalCount int64
	var channelRows []models.SearchChannelsRow
	var response *SearchChannelsResponse

	err := tracing.NewOperation("channel_search").
		WithContext(ctx).
		WithAttributes(map[string]interface{}{
			"user_id": claims.UserID,
			"query":   req.Query,
		}).
		AddStage("get_search_count", func(tc *tracing.TracedContext) error {
			var err error
			totalCount, err = ctr.s.SearchChannelsCount(tc.Context, searchQuery)
			if err != nil {
				logger.Error("Failed to get channel search count",
					"userID", claims.UserID,
					"query", searchQuery,
					"error", err.Error())
				tc.RecordError(err)
				return apierrors.HandleDatabaseError(c, err)
			}
			tc.AddAttr("search.total_count", totalCount)
			tc.MarkSuccess()
			return nil
		}).
		AddStage("execute_search", func(tc *tracing.TracedContext) error {
			searchParams := models.SearchChannelsParams{
				Name:   searchQuery,
				Limit:  helper.SafeInt32(req.Limit),
				Offset: helper.SafeInt32(req.Offset),
			}

			tc.AddAttrs(map[string]interface{}{
				"search.original_query": req.Query,
				"search.prepared_query": searchQuery,
				"search.limit":          req.Limit,
				"search.offset":         req.Offset,
				"search.user_id":        int64(claims.UserID),
				"search.user_agent":     c.Request().UserAgent(),
				"search.client_ip":      c.RealIP(),
				"search.has_wildcards":  strings.Contains(req.Query, "*") || strings.Contains(req.Query, "?"),
				"search.query_length":   len(req.Query),
			})

			var err error
			channelRows, err = ctr.s.SearchChannels(tc.Context, searchParams)
			if err != nil {
				logger.Error("Failed to search channels",
					"userID", claims.UserID,
					"searchParams", searchParams,
					"error", err.Error())
				tc.AddAttrs(map[string]interface{}{
					"search.query_success":  false,
					"search.database_error": err.Error(),
				})
				tc.RecordError(err)
				return apierrors.HandleDatabaseError(c, err)
			}

			tc.AddAttrs(map[string]interface{}{
				"search.query_success":    true,
				"search.raw_result_count": len(channelRows),
			})
			tc.MarkSuccess()
			return nil
		}).
		AddStage("format_results", func(tc *tracing.TracedContext) error {
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

			hasMore := int64(req.Offset+req.Limit) < totalCount

			tc.AddAttrs(map[string]interface{}{
				"results.formatted_count":           len(channels),
				"results.channels_with_description": channelsWithDescription,
				"results.channels_with_url":         channelsWithURL,
				"results.total_member_count":        totalMemberCount,
				"results.total_available":           totalCount,
				"results.has_more":                  hasMore,
			})

			if len(channels) > 0 {
				tc.AddAttrs(map[string]interface{}{
					"results.description_ratio": float64(channelsWithDescription) / float64(len(channels)),
					"results.url_ratio":         float64(channelsWithURL) / float64(len(channels)),
					"results.avg_member_count":  float64(totalMemberCount) / float64(len(channels)),
				})
			}

			response = &SearchChannelsResponse{
				Channels: channels,
				Pagination: PaginationInfo{
					Total:   int(totalCount),
					Limit:   req.Limit,
					Offset:  req.Offset,
					HasMore: hasMore,
				},
			}

			tc.MarkSuccess()
			return nil
		}).
		Execute()

	if err != nil {
		return err
	}

	logger.Info("Channel search completed successfully",
		"userID", claims.UserID,
		"query", req.Query,
		"resultCount", len(channelRows))

	return c.JSON(http.StatusOK, response)
}

// UpdateChannelSettings handles channel settings update requests (full replacement)
// @Summary Update all channel settings
// @Description Replace all channel settings with new values. Requires access level 500 to modify level 500 settings (autojoin, massdeoppro, noop, strictop) and level 450 for remaining settings.
// @Tags channels
// @Accept json
// @Produce json
// @Param id path int true "Channel ID"
// @Param settings body channel.FullSettingsRequest true "Complete channel settings"
// @Success 200 {object} channel.UpdateChannelSettingsResponse
// @Failure 400 {object} errors.ErrorResponse "Invalid request data"
// @Failure 401 {object} errors.ErrorResponse "Authorization information is missing or invalid"
// @Failure 403 {object} errors.ErrorResponse "Insufficient permissions - includes denied_settings in details when specific settings are denied"
// @Failure 404 {object} errors.ErrorResponse "Channel not found"
// @Failure 500 {object} errors.ErrorResponse "Internal server error"
// @Router /channels/{id} [put]
// @Security JWTBearerToken
func (ctr *ChannelController) UpdateChannelSettings(c echo.Context) error {
	logger := helper.GetRequestLogger(c)

	userToken := c.Get("user")
	if userToken == nil {
		return apierrors.HandleUnauthorizedError(c, "Authorization information is missing or invalid")
	}

	claims := helper.GetClaimsFromContext(c)
	if claims == nil {
		return apierrors.HandleUnauthorizedError(c, "Authorization information is missing or invalid")
	}

	channelIDParam := c.Param("id")
	if channelIDParam == "" {
		return apierrors.HandleBadRequestError(c, "Channel ID is required")
	}

	channelID, err := strconv.ParseInt(channelIDParam, 10, 32)
	if err != nil || channelID <= 0 {
		return apierrors.HandleBadRequestError(c, "Invalid channel ID")
	}

	var req channel.FullSettingsRequest
	if err := c.Bind(&req); err != nil {
		logger.Error("Failed to parse request body",
			"userID", claims.UserID,
			"channelID", channelID,
			"error", err.Error())
		return apierrors.HandleBadRequestError(c, "Invalid request body")
	}

	if err := c.Validate(&req); err != nil {
		return apierrors.HandleValidationError(c, err)
	}
	ctx, cancel := context.WithTimeout(c.Request().Context(), 10*time.Second)
	defer cancel()

	_, err = ctr.s.CheckChannelExists(ctx, int32(channelID))
	if err != nil {
		logger.Error("Channel not found",
			"userID", claims.UserID,
			"channelID", channelID,
			"error", err.Error())
		return apierrors.HandleNotFoundError(c, "Channel")
	}

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

	if err := channel.CheckAccessForFullRequest(userAccess.Access); err != nil {
		if accessErr, ok := err.(*channel.AccessDeniedError); ok {
			logger.Warn("User lacks permission for some settings",
				"userID", claims.UserID,
				"channelID", channelID,
				"accessLevel", userAccess.Access,
				"deniedCount", len(accessErr.DeniedSettings))
			return apierrors.HandleSettingsAccessDeniedError(c, accessErr)
		}
		return apierrors.HandleInternalError(c, err, "Failed to check settings access")
	}

	currentChannel, err := ctr.s.GetChannelSettingsForAPI(ctx, int32(channelID))
	if err != nil {
		logger.Error("Failed to get current channel data",
			"userID", claims.UserID,
			"channelID", channelID,
			"error", err.Error())
		return apierrors.HandleDatabaseError(c, err)
	}

	newFlags := currentChannel.Flags
	if req.Autojoin {
		newFlags.AddFlag(flags.ChannelAutoJoin)
	} else {
		newFlags.RemoveFlag(flags.ChannelAutoJoin)
	}
	if req.Noop {
		newFlags.AddFlag(flags.ChannelNoOp)
	} else {
		newFlags.RemoveFlag(flags.ChannelNoOp)
	}
	if req.Strictop {
		newFlags.AddFlag(flags.ChannelStrictOp)
	} else {
		newFlags.RemoveFlag(flags.ChannelStrictOp)
	}
	if req.Autotopic {
		newFlags.AddFlag(flags.ChannelAutoTopic)
	} else {
		newFlags.RemoveFlag(flags.ChannelAutoTopic)
	}
	if req.Floatlim {
		newFlags.AddFlag(flags.ChannelFloatLimit)
	} else {
		newFlags.RemoveFlag(flags.ChannelFloatLimit)
	}

	updateParams := models.UpdateAllChannelSettingsParams{
		ID:          int32(channelID),
		Flags:       newFlags,
		MassDeopPro: int16(req.Massdeoppro), //nolint:gosec // Validated: 0-7
		Description: db.NewString(req.Description),
		Url:         db.NewString(req.URL),
		Keywords:    db.NewString(req.Keywords),
		Userflags:   flags.ChannelUser(req.Userflags), //nolint:gosec // Validated: 0-2
		LimitOffset: db.NewInt4(int64(req.Floatmargin)),
		LimitPeriod: db.NewInt4(int64(req.Floatperiod)),
		LimitGrace:  db.NewInt4(int64(req.Floatgrace)),
		LimitMax:    db.NewInt4(int64(req.Floatmax)),
	}

	updatedChannel, err := ctr.s.UpdateAllChannelSettings(ctx, updateParams)
	if err != nil {
		logger.Error("Failed to update channel",
			"userID", claims.UserID,
			"channelID", channelID,
			"error", err.Error())
		return apierrors.HandleDatabaseError(c, err)
	}

	logger.Info("User updated channel settings",
		"userID", claims.UserID,
		"channelID", channelID)

	response := channel.UpdateChannelSettingsResponse{
		ID:          updatedChannel.ID,
		Name:        updatedChannel.Name,
		MemberCount: helper.SafeInt32FromInt64(currentChannel.MemberCount),
		CreatedAt:   db.Int4ToInt32(updatedChannel.RegisteredTs),
		UpdatedAt:   updatedChannel.LastUpdated,
		Settings: channel.ResponseSettings{
			Autojoin:    updatedChannel.Flags.HasFlag(flags.ChannelAutoJoin),
			Massdeoppro: int(updatedChannel.MassDeopPro),
			Noop:        updatedChannel.Flags.HasFlag(flags.ChannelNoOp),
			Strictop:    updatedChannel.Flags.HasFlag(flags.ChannelStrictOp),
			Autotopic:   updatedChannel.Flags.HasFlag(flags.ChannelAutoTopic),
			Description: db.TextToString(updatedChannel.Description),
			Floatlim:    updatedChannel.Flags.HasFlag(flags.ChannelFloatLimit),
			Floatgrace:  db.Int4ToInt(updatedChannel.LimitGrace),
			Floatmargin: db.Int4ToInt(updatedChannel.LimitOffset),
			Floatmax:    db.Int4ToInt(updatedChannel.LimitMax),
			Floatperiod: db.Int4ToInt(updatedChannel.LimitPeriod),
			Keywords:    db.TextToString(updatedChannel.Keywords),
			URL:         db.TextToString(updatedChannel.Url),
			Userflags:   int(updatedChannel.Userflags),
		},
	}

	return c.JSON(http.StatusOK, response)
}

// GetChannelSettings handles retrieving channel settings
// @Summary Get channel settings
// @Description Retrieve current channel settings including all configurable options. Requires minimum access level 100 on the channel.
// @Tags channels
// @Accept json
// @Produce json
// @Param id path int true "Channel ID"
// @Success 200 {object} channel.GetChannelSettingsResponse
// @Failure 400 {object} errors.ErrorResponse "Invalid channel ID"
// @Failure 401 {object} errors.ErrorResponse "Authorization information is missing or invalid"
// @Failure 403 {object} errors.ErrorResponse "Insufficient permissions to view channel"
// @Failure 404 {object} errors.ErrorResponse "Channel not found"
// @Failure 500 {object} errors.ErrorResponse "Internal server error"
// @Router /channels/{id} [get]
// @Security JWTBearerToken
func (ctr *ChannelController) GetChannelSettings(c echo.Context) error {
	logger := helper.GetRequestLogger(c)

	userToken := c.Get("user")
	if userToken == nil {
		return apierrors.HandleUnauthorizedError(c, "Authorization information is missing or invalid")
	}

	claims := helper.GetClaimsFromContext(c)
	if claims == nil {
		return apierrors.HandleUnauthorizedError(c, "Authorization information is missing or invalid")
	}

	channelIDParam := c.Param("id")
	if channelIDParam == "" {
		return apierrors.HandleBadRequestError(c, "Channel ID is required")
	}

	channelID, err := strconv.ParseInt(channelIDParam, 10, 32)
	if err != nil || channelID <= 0 {
		return apierrors.HandleBadRequestError(c, "Invalid channel ID")
	}

	ctx, cancel := context.WithTimeout(c.Request().Context(), 5*time.Second)
	defer cancel()

	channelData, err := ctr.s.GetChannelSettingsForAPI(ctx, int32(channelID))
	if err != nil {
		logger.Error("Channel not found",
			"userID", claims.UserID,
			"channelID", channelID,
			"error", err.Error())
		return apierrors.HandleNotFoundError(c, "Channel")
	}

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

	logger.Info("User viewed channel settings",
		"userID", claims.UserID,
		"channelID", channelID)

	response := channel.GetChannelSettingsResponse{
		ID:          channelData.ID,
		Name:        channelData.Name,
		MemberCount: helper.SafeInt32FromInt64(channelData.MemberCount),
		CreatedAt:   db.Int4ToInt32(channelData.RegisteredTs),
		Settings: channel.ResponseSettings{
			Autojoin:    channelData.Flags.HasFlag(flags.ChannelAutoJoin),
			Massdeoppro: int(channelData.MassDeopPro),
			Noop:        channelData.Flags.HasFlag(flags.ChannelNoOp),
			Strictop:    channelData.Flags.HasFlag(flags.ChannelStrictOp),
			Autotopic:   channelData.Flags.HasFlag(flags.ChannelAutoTopic),
			Description: db.TextToString(channelData.Description),
			Floatlim:    channelData.Flags.HasFlag(flags.ChannelFloatLimit),
			Floatgrace:  db.Int4ToInt(channelData.LimitGrace),
			Floatmargin: db.Int4ToInt(channelData.LimitOffset),
			Floatmax:    db.Int4ToInt(channelData.LimitMax),
			Floatperiod: db.Int4ToInt(channelData.LimitPeriod),
			Keywords:    db.TextToString(channelData.Keywords),
			URL:         db.TextToString(channelData.Url),
			Userflags:   int(channelData.Userflags),
		},
	}

	if channelData.LastUpdated > 0 {
		response.UpdatedAt = channelData.LastUpdated
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
	UserID      int64 `json:"user_id"      validate:"required"`
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
		return apierrors.HandleUnprocessableEntityError(
			c,
			"Cannot add user with access level higher than or equal to your own",
		)
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
	Description string   `json:"description"  validate:"required,max=300"`
	Supporters  []string `json:"supporters"   validate:"required,min=1"`
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
			Status:        "pending_confirmation",
			SubmittedAt:   time.Unix(int64(pendingRegistration.CreatedTs), 0),
			ApplicationID: int64(pendingRegistration.ChannelID),
		},
		Status: "success",
	}

	return c.JSON(http.StatusCreated, response)
}

// ManagerChangeRequest represents the request to change channel management
type ManagerChangeRequest struct {
	NewManagerUsername string `json:"new_manager_username"     validate:"required,min=2,max=12,ircusername"`
	ChangeType         string `json:"change_type"              validate:"required,oneof=temporary permanent"`
	DurationWeeks      *int   `json:"duration_weeks,omitempty" validate:"omitempty,min=3,max=7"`
	Reason             string `json:"reason"                   validate:"required,min=1,max=500,nocontrolchars,meaningful"`
}

// ManagerChangeResponse represents the response after submitting manager change request
type ManagerChangeResponse struct {
	Data   ManagerChangeData `json:"data"`
	Status string            `json:"status"`
}

// ManagerChangeData contains the manager change response data
type ManagerChangeData struct {
	ChannelID     int32     `json:"channel_id"               extensions:"x-order=0"`
	ChangeType    string    `json:"change_type"              extensions:"x-order=1"`
	NewManager    string    `json:"new_manager"              extensions:"x-order=2"`
	DurationWeeks *int      `json:"duration_weeks,omitempty" extensions:"x-order=3"`
	Reason        string    `json:"reason"                   extensions:"x-order=4"`
	SubmittedAt   time.Time `json:"submitted_at"             extensions:"x-order=5"`
	ExpiresAt     time.Time `json:"expires_at"               extensions:"x-order=6"`
	Status        string    `json:"status"                   extensions:"x-order=7"`
}

// ManagerChangeConfirmationResponse represents the response for confirming a manager change
type ManagerChangeConfirmationResponse struct {
	Status  string                        `json:"status"`
	Message string                        `json:"message"`
	Data    ManagerChangeConfirmationData `json:"data"`
}

// ManagerChangeConfirmationData contains the confirmation response data
type ManagerChangeConfirmationData struct {
	ChannelID   int32  `json:"channel_id"`
	ChannelName string `json:"channel_name"`
	RequestID   int32  `json:"request_id"`
	ChangeType  string `json:"change_type"`
	Status      string `json:"status"`
}

// RequestManagerChange handles manager change requests for channels
// @Summary Submit a manager change request
// @Description Submit a request to change channel management (temporary or permanent)
// @Tags channels
// @Accept json
// @Produce json
// @Param id path int true "Channel ID"
// @Param request body ManagerChangeRequest true "Manager change request data"
// @Success 201 {object} ManagerChangeResponse
// @Failure 400 {string} string "Invalid request data or validation failure"
// @Failure 401 {string} string "Authorization information is missing or invalid"
// @Failure 403 {string} string "Insufficient permissions or business rule violation"
// @Failure 409 {string} string "Conflicting pending request exists"
// @Failure 429 {string} string "User in cooldown period"
// @Failure 500 {string} string "Internal server error"
// @Router /channels/{id}/manager-change [post]
// @Security JWTBearerToken
func (ctr *ChannelController) RequestManagerChange(c echo.Context) error {
	logger := helper.GetRequestLogger(c)
	ctx, cancel := context.WithTimeout(c.Request().Context(), 30*time.Second)
	defer cancel()

	userToken := c.Get("user")
	if userToken == nil {
		return apierrors.HandleUnauthorizedError(c, "Authorization information is missing or invalid")
	}

	claims := helper.GetClaimsFromContext(c)
	if claims == nil {
		return apierrors.HandleUnauthorizedError(c, "Authorization information is missing or invalid")
	}

	channelIDParam := c.Param("id")
	channelID, err := strconv.ParseInt(channelIDParam, 10, 32)
	if err != nil {
		logger.Error("Invalid channel ID in path",
			"userID", claims.UserID,
			"channelID", channelIDParam,
			"error", err.Error())
		return apierrors.HandleBadRequestError(c, "Invalid channel ID")
	}

	req := new(ManagerChangeRequest)
	if err := c.Bind(req); err != nil {
		logger.Error("Failed to parse manager change request body",
			"userID", claims.UserID,
			"channelID", channelID,
			"error", err.Error())
		return apierrors.HandleBadRequestError(c, "Invalid request body")
	}

	if err := c.Validate(req); err != nil {
		return apierrors.HandleValidationError(c, err)
	}

	// Additional validation: temporary changes must have duration
	if req.ChangeType == "temporary" && req.DurationWeeks == nil {
		return apierrors.HandleBadRequestError(c, "Duration in weeks is required for temporary changes")
	}
	// Additional validation: permanent changes cannot have duration
	if req.ChangeType == "permanent" && req.DurationWeeks != nil {
		return apierrors.HandleBadRequestError(c, "Duration cannot be specified for permanent changes")
	}

	normalizedNewManager := strings.ToLower(strings.TrimSpace(req.NewManagerUsername))
	if normalizedNewManager == "" {
		return apierrors.HandleBadRequestError(c, "New manager username cannot be empty or contain only whitespace")
	}

	if strings.EqualFold(normalizedNewManager, claims.Username) {
		return apierrors.HandleBadRequestError(c, "You cannot assign yourself as the new manager")
	}

	logger.Info("User requesting manager change",
		"userID", claims.UserID,
		"username", claims.Username,
		"channelID", channelID,
		"newManager", req.NewManagerUsername,
		"changeType", req.ChangeType,
		"durationWeeks", req.DurationWeeks)

	validator := helper.NewManagerChangeValidator(ctr.s)
	errorHandler := apierrors.NewManagerChangeErrorHandler()

	if err := validator.ValidateManagerChangeBusinessRules(ctx, int32(channelID), claims.UserID, normalizedNewManager, req.ChangeType); err != nil {
		if validationErr, ok := err.(*helper.ValidationError); ok {
			logger.Warn("Manager change request failed business rule validation",
				"userID", claims.UserID,
				"channelID", channelID,
				"newManager", req.NewManagerUsername,
				"validationCode", validationErr.Code,
				"validationMessage", validationErr.Message)
		}
		return errorHandler.HandleBusinessRuleError(c, err)
	}

	newManager, err := ctr.s.GetUser(ctx, models.GetUserParams{
		Username: normalizedNewManager,
	})
	if err != nil {
		return apierrors.HandleDatabaseError(c, err)
	}

	currentManager, err := ctr.s.GetUser(ctx, models.GetUserParams{
		ID: claims.UserID,
	})
	if err != nil {
		return apierrors.HandleDatabaseError(c, err)
	}

	confirmationToken := helper.GenerateSecureToken(64)
	expirationTime := time.Now().Add(6 * time.Hour)

	var optDuration int32
	if req.ChangeType == "temporary" && req.DurationWeeks != nil {
		// Calculate duration safely to avoid integer overflow
		weeks := int64(*req.DurationWeeks)
		seconds := weeks * 7 * 24 * 3600
		if seconds > int64(^uint32(0)>>1) { // Check if exceeds int32 max
			return apierrors.HandleBadRequestError(c, "Duration too large")
		}
		optDuration = int32(seconds) //nolint:gosec // Overflow check performed above
	}

	// Convert change type to integer (0=temporary, 1=permanent)
	var changeTypeInt int16
	if req.ChangeType == "permanent" {
		changeTypeInt = 1
	}

	clientIP := c.RealIP()
	if clientIP == "" {
		clientIP = "0.0.0.0"
	}

	_, err = ctr.s.InsertManagerChangeRequest(ctx, models.InsertManagerChangeRequestParams{
		ChannelID:    int32(channelID),
		ManagerID:    claims.UserID,
		NewManagerID: newManager.ID,
		ChangeType:   pgtype.Int2{Int16: changeTypeInt, Valid: true},
		OptDuration:  pgtype.Int4{Int32: optDuration, Valid: true},
		Reason:       pgtype.Text{String: req.Reason, Valid: true},
		Expiration: pgtype.Int4{
			Int32: helper.SafeInt32FromInt64(expirationTime.Unix()),
			Valid: true,
		},
		Crc:      pgtype.Text{String: confirmationToken, Valid: true},
		FromHost: pgtype.Text{String: clientIP, Valid: true},
	})
	if err != nil {
		logger.Error("Failed to insert manager change request",
			"userID", claims.UserID,
			"channelID", channelID,
			"error", err.Error())
		return apierrors.HandleDatabaseError(c, err)
	}

	err = ctr.s.UpdateUserCooldown(ctx, claims.UserID, time.Now().Unix()+86400*10)
	if err != nil {
		logger.Warn("Failed to update user cooldown",
			"userID", claims.UserID,
			"error", err.Error())
	}

	if currentManager.Email.Valid && currentManager.Email.String != "" {
		channelInfo, err := ctr.s.CheckChannelExistsAndRegistered(ctx, int32(channelID))
		if err != nil {
			logger.Warn("Failed to get channel info for email",
				"channelID", channelID,
				"error", err.Error())
		} else {
			confirmationURL := fmt.Sprintf("https://cservice.undernet.org/manager-change/confirm?token=%s", confirmationToken)

			templateData := map[string]any{
				"CurrentManagerUsername": currentManager.Username,
				"ChannelName":            channelInfo.Name,
				"NewManagerUsername":     req.NewManagerUsername,
				"ChangeType":             req.ChangeType,
				"DurationWeeks":          req.DurationWeeks,
				"Reason":                 req.Reason,
				"SubmittedAt":            time.Now().Format("2006-01-02 15:04:05 UTC"),
				"ExpiresAt":              expirationTime.Format("2006-01-02 15:04:05 UTC"),
				"ConfirmationURL":        confirmationURL,
				"Year":                   time.Now().Year(),
			}

			m := mail.NewMail(
				currentManager.Email.String,
				fmt.Sprintf("Channel Manager Change Request - #%s", channelInfo.Name),
				"manager_change",
				templateData,
			)

			if err := m.Send(); err != nil {
				logger.Error("Failed to send manager change confirmation email",
					"userID", claims.UserID,
					"channelID", channelID,
					"email", currentManager.Email.String,
					"error", err.Error())
			} else {
				logger.Info("Manager change confirmation email sent successfully",
					"userID", claims.UserID,
					"channelID", channelID,
					"email", currentManager.Email.String)
			}
		}
	} else {
		logger.Warn("Current manager has no valid email address for confirmation",
			"userID", claims.UserID,
			"channelID", channelID)
	}

	response := ManagerChangeResponse{
		Data: ManagerChangeData{
			ChannelID:     int32(channelID),
			ChangeType:    req.ChangeType,
			NewManager:    req.NewManagerUsername,
			DurationWeeks: req.DurationWeeks,
			Reason:        req.Reason,
			SubmittedAt:   time.Now(),
			ExpiresAt:     expirationTime,
			Status:        "pending_confirmation",
		},
		Status: "success",
	}

	logger.Info("Manager change request submitted successfully",
		"userID", claims.UserID,
		"channelID", channelID,
		"newManager", req.NewManagerUsername,
		"changeType", req.ChangeType,
		"token", confirmationToken[:8]+"...") // Log only first 8 chars for security

	return c.JSON(http.StatusCreated, response)
}

func getChangeTypeString(changeType int16) string {
	if changeType == 0 {
		return "temporary"
	}
	return "permanent"
}

// ManagerChangeStatusResponse represents the response for checking status of manager change requests
type ManagerChangeStatusResponse struct {
	RequestID     *int32     `json:"request_id,omitempty"`
	ChannelID     *int32     `json:"channel_id,omitempty"`
	ChangeType    *string    `json:"change_type,omitempty"`
	NewManager    *string    `json:"new_manager,omitempty"`
	DurationWeeks *int       `json:"duration_weeks,omitempty"`
	Reason        *string    `json:"reason,omitempty"`
	Status        *string    `json:"status,omitempty"`
	SubmittedAt   *time.Time `json:"submitted_at,omitempty"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
}

// GetManagerChangeStatus handles checking the status of pending manager change requests
// @Summary Get manager change request status
// @Description Check the status of pending manager change requests for a channel
// @Tags channels
// @Accept json
// @Produce json
// @Param id path int true "Channel ID"
// @Success 200 {object} ManagerChangeStatusResponse
// @Failure 400 {string} string "Invalid channel ID"
// @Failure 401 {string} string "Authorization information is missing or invalid"
// @Failure 403 {string} string "Insufficient permissions to view status"
// @Failure 404 {string} string "No pending requests found"
// @Failure 500 {string} string "Internal server error"
// @Router /channels/{id}/manager-change-status [get]
// @Security JWTBearerToken
func (ctr *ChannelController) GetManagerChangeStatus(c echo.Context) error {
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

	// Check if channel exists
	_, err = ctr.s.CheckChannelExists(ctx, int32(channelID))
	if err != nil {
		logger.Error("Channel not found",
			"userID", claims.UserID,
			"channelID", channelID,
			"error", err.Error())
		return apierrors.HandleNotFoundError(c, "Channel")
	}

	// Check user access level - must have at least level 1 (any access) to view status
	// This ensures only channel members can view manager change status
	userAccess, err := ctr.s.GetChannelUserAccess(ctx, int32(channelID), claims.UserID)
	if err != nil {
		logger.Error("Failed to get user access for channel",
			"userID", claims.UserID,
			"channelID", channelID,
			"error", err.Error())
		return apierrors.HandleForbiddenError(c, "Insufficient permissions to view manager change status")
	}

	if userAccess.Access < 1 {
		logger.Warn("User attempted to view manager change status with no channel access",
			"userID", claims.UserID,
			"channelID", channelID,
			"accessLevel", userAccess.Access)
		return apierrors.HandleForbiddenError(c, "Insufficient permissions to view manager change status")
	}

	// Get the latest pending manager change request status
	requestStatus, err := ctr.s.GetManagerChangeRequestStatus(ctx, int32(channelID))
	if err != nil {
		logger.Info("No pending manager change requests found",
			"userID", claims.UserID,
			"channelID", channelID)
		// Return empty response when no requests found
		response := ManagerChangeStatusResponse{}
		return c.JSON(http.StatusOK, response)
	}

	// Determine the status string based on confirmed value
	var statusString string
	switch requestStatus.Confirmed.Int16 {
	case 0:
		statusString = "pending_confirmation"
	case 1:
		statusString = "confirmed"
	default:
		statusString = "unknown"
	}

	// Convert change type to string
	changeTypeString := getChangeTypeString(requestStatus.ChangeType.Int16)

	// Calculate duration in weeks for temporary changes
	var durationWeeks *int
	if requestStatus.ChangeType.Int16 == 0 && requestStatus.OptDuration.Valid {
		weeks := int(requestStatus.OptDuration.Int32 / (7 * 24 * 3600))
		durationWeeks = &weeks
	}

	// Calculate submitted time (we don't have created_ts in the query, so use expiration - 6 hours)
	submittedAt := time.Unix(int64(requestStatus.Expiration.Int32), 0).Add(-6 * time.Hour)
	expiresAt := time.Unix(int64(requestStatus.Expiration.Int32), 0)

	// Log the status check for audit purposes
	logger.Info("User viewed manager change request status",
		"userID", claims.UserID,
		"channelID", channelID,
		"requestID", requestStatus.ID.Int32,
		"status", statusString)

	// Prepare response
	response := ManagerChangeStatusResponse{
		RequestID:     &requestStatus.ID.Int32,
		ChannelID:     &requestStatus.ChannelID,
		ChangeType:    &changeTypeString,
		NewManager:    &requestStatus.NewManagerUsername,
		DurationWeeks: durationWeeks,
		Reason:        &requestStatus.Reason.String,
		Status:        &statusString,
		SubmittedAt:   &submittedAt,
		ExpiresAt:     &expiresAt,
	}

	return c.JSON(http.StatusOK, response)
}

// PatchChannelSettings handles partial channel settings update requests
// @Summary Partially update channel settings
// @Description Update only the provided channel settings. Fields not included in the request remain unchanged. Requires access level 500 to modify level 500 settings (autojoin, massdeoppro, noop, strictop) and level 450 for remaining settings.
// @Tags channels
// @Accept json
// @Produce json
// @Param id path int true "Channel ID"
// @Param settings body channel.PartialSettingsRequest true "Partial channel settings to update"
// @Success 200 {object} channel.UpdateChannelSettingsResponse
// @Failure 400 {object} errors.ErrorResponse "Invalid request data"
// @Failure 401 {object} errors.ErrorResponse "Authorization information is missing or invalid"
// @Failure 403 {object} errors.ErrorResponse "Insufficient permissions - includes denied_settings in details when specific settings are denied"
// @Failure 404 {object} errors.ErrorResponse "Channel not found"
// @Failure 500 {object} errors.ErrorResponse "Internal server error"
// @Router /channels/{id} [patch]
// @Security JWTBearerToken
func (ctr *ChannelController) PatchChannelSettings(c echo.Context) error {
	logger := helper.GetRequestLogger(c)

	userToken := c.Get("user")
	if userToken == nil {
		return apierrors.HandleUnauthorizedError(c, "Authorization information is missing or invalid")
	}

	claims := helper.GetClaimsFromContext(c)
	if claims == nil {
		return apierrors.HandleUnauthorizedError(c, "Authorization information is missing or invalid")
	}

	channelIDParam := c.Param("id")
	if channelIDParam == "" {
		return apierrors.HandleBadRequestError(c, "Channel ID is required")
	}

	channelID, err := strconv.ParseInt(channelIDParam, 10, 32)
	if err != nil || channelID <= 0 {
		return apierrors.HandleBadRequestError(c, "Invalid channel ID")
	}

	var req channel.PartialSettingsRequest
	if err := c.Bind(&req); err != nil {
		logger.Error("Failed to parse request body",
			"userID", claims.UserID,
			"channelID", channelID,
			"error", err.Error())
		return apierrors.HandleBadRequestError(c, "Invalid request body")
	}

	if err := c.Validate(&req); err != nil {
		return apierrors.HandleValidationError(c, err)
	}
	ctx, cancel := context.WithTimeout(c.Request().Context(), 10*time.Second)
	defer cancel()

	currentChannel, err := ctr.s.GetChannelSettingsForAPI(ctx, int32(channelID))
	if err != nil {
		logger.Error("Channel not found",
			"userID", claims.UserID,
			"channelID", channelID,
			"error", err.Error())
		return apierrors.HandleNotFoundError(c, "Channel")
	}

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

	if err := channel.CheckAccessForPartialRequest(userAccess.Access, &req); err != nil {
		if accessErr, ok := err.(*channel.AccessDeniedError); ok {
			logger.Warn("User lacks permission for some settings",
				"userID", claims.UserID,
				"channelID", channelID,
				"accessLevel", userAccess.Access,
				"deniedCount", len(accessErr.DeniedSettings))
			return apierrors.HandleSettingsAccessDeniedError(c, accessErr)
		}
		return apierrors.HandleInternalError(c, err, "Failed to check settings access")
	}

	newFlags := currentChannel.Flags
	if req.Autojoin != nil {
		if *req.Autojoin {
			newFlags.AddFlag(flags.ChannelAutoJoin)
		} else {
			newFlags.RemoveFlag(flags.ChannelAutoJoin)
		}
	}
	if req.Noop != nil {
		if *req.Noop {
			newFlags.AddFlag(flags.ChannelNoOp)
		} else {
			newFlags.RemoveFlag(flags.ChannelNoOp)
		}
	}
	if req.Strictop != nil {
		if *req.Strictop {
			newFlags.AddFlag(flags.ChannelStrictOp)
		} else {
			newFlags.RemoveFlag(flags.ChannelStrictOp)
		}
	}
	if req.Autotopic != nil {
		if *req.Autotopic {
			newFlags.AddFlag(flags.ChannelAutoTopic)
		} else {
			newFlags.RemoveFlag(flags.ChannelAutoTopic)
		}
	}
	if req.Floatlim != nil {
		if *req.Floatlim {
			newFlags.AddFlag(flags.ChannelFloatLimit)
		} else {
			newFlags.RemoveFlag(flags.ChannelFloatLimit)
		}
	}

	patchParams := models.PatchChannelSettingsParams{
		ID:    int32(channelID),
		Flags: newFlags,
	}

	if req.Massdeoppro != nil {
		patchParams.MassDeopPro = int16(*req.Massdeoppro) //nolint:gosec // Validated: 0-7
	}
	if req.Description != nil {
		patchParams.Description = pgtype.Text{String: *req.Description, Valid: true}
	}
	if req.URL != nil {
		patchParams.Url = pgtype.Text{String: *req.URL, Valid: true}
	}
	if req.Keywords != nil {
		patchParams.Keywords = pgtype.Text{String: *req.Keywords, Valid: true}
	}
	if req.Userflags != nil {
		patchParams.Userflags = flags.ChannelUser(*req.Userflags) //nolint:gosec // Validated: 0-2
	}
	if req.Floatmargin != nil {
		patchParams.LimitOffset = db.NewInt4(int64(*req.Floatmargin))
	}
	if req.Floatperiod != nil {
		patchParams.LimitPeriod = db.NewInt4(int64(*req.Floatperiod))
	}
	if req.Floatgrace != nil {
		patchParams.LimitGrace = db.NewInt4(int64(*req.Floatgrace))
	}
	if req.Floatmax != nil {
		patchParams.LimitMax = db.NewInt4(int64(*req.Floatmax))
	}

	updatedChannel, err := ctr.s.PatchChannelSettings(ctx, patchParams)
	if err != nil {
		logger.Error("Failed to update channel",
			"userID", claims.UserID,
			"channelID", channelID,
			"error", err.Error())
		return apierrors.HandleDatabaseError(c, err)
	}

	logger.Info("User patched channel settings",
		"userID", claims.UserID,
		"channelID", channelID)

	response := channel.UpdateChannelSettingsResponse{
		ID:          updatedChannel.ID,
		Name:        updatedChannel.Name,
		MemberCount: helper.SafeInt32FromInt64(currentChannel.MemberCount),
		CreatedAt:   db.Int4ToInt32(updatedChannel.RegisteredTs),
		UpdatedAt:   updatedChannel.LastUpdated,
		Settings: channel.ResponseSettings{
			Autojoin:    updatedChannel.Flags.HasFlag(flags.ChannelAutoJoin),
			Massdeoppro: int(updatedChannel.MassDeopPro),
			Noop:        updatedChannel.Flags.HasFlag(flags.ChannelNoOp),
			Strictop:    updatedChannel.Flags.HasFlag(flags.ChannelStrictOp),
			Autotopic:   updatedChannel.Flags.HasFlag(flags.ChannelAutoTopic),
			Description: db.TextToString(updatedChannel.Description),
			Floatlim:    updatedChannel.Flags.HasFlag(flags.ChannelFloatLimit),
			Floatgrace:  db.Int4ToInt(updatedChannel.LimitGrace),
			Floatmargin: db.Int4ToInt(updatedChannel.LimitOffset),
			Floatmax:    db.Int4ToInt(updatedChannel.LimitMax),
			Floatperiod: db.Int4ToInt(updatedChannel.LimitPeriod),
			Keywords:    db.TextToString(updatedChannel.Keywords),
			URL:         db.TextToString(updatedChannel.Url),
			Userflags:   int(updatedChannel.Userflags),
		},
	}

	return c.JSON(http.StatusOK, response)
}

// ConfirmManagerChange handles manager change confirmation via email token
// @Summary Confirm a manager change request
// @Description Confirm a manager change request using the token from the confirmation email
// @Tags channels
// @Accept json
// @Produce json
// @Param id path int true "Channel ID"
// @Param token query string true "Confirmation token from email"
// @Success 200 {object} ManagerChangeConfirmationResponse
// @Failure 400 {object} errors.ErrorResponse "Invalid or expired token"
// @Failure 404 {object} errors.ErrorResponse "Channel or token not found"
// @Router /channels/{id}/manager-confirm [get]
func (ctr *ChannelController) ConfirmManagerChange(c echo.Context) error {
	logger := helper.GetRequestLogger(c)
	ctx, cancel := context.WithTimeout(c.Request().Context(), 30*time.Second)
	defer cancel()

	channelIDParam := c.Param("id")
	channelID, err := strconv.ParseInt(channelIDParam, 10, 32)
	if err != nil {
		logger.Error("Invalid channel ID in confirmation request",
			"channelID", channelIDParam,
			"error", err.Error())
		return apierrors.HandleBadRequestError(c, "Invalid channel ID")
	}

	token := c.QueryParam("token")
	if token == "" {
		logger.Error("Missing confirmation token", "channelID", channelID)
		return apierrors.HandleBadRequestError(c, "Missing confirmation token")
	}

	logger.Info("Processing manager change confirmation",
		"channelID", channelID,
		"token", token[:8]+"...")

	err = ctr.s.CleanupExpiredManagerChangeRequests(ctx)
	if err != nil {
		logger.Warn("Failed to cleanup expired requests",
			"channelID", channelID,
			"error", err.Error())
	}

	tokenText := pgtype.Text{
		String: token,
		Valid:  true,
	}

	request, err := ctr.s.GetManagerChangeRequestByToken(ctx, tokenText)
	if err != nil {
		logger.Warn("Invalid or expired confirmation token",
			"channelID", channelID,
			"token", token[:8]+"...",
			"error", err.Error())
		return apierrors.HandleBadRequestError(c, "Invalid or expired confirmation token")
	}

	if request.ChannelID != int32(channelID) {
		logger.Warn("Channel ID mismatch in confirmation",
			"requestChannelID", request.ChannelID,
			"urlChannelID", channelID,
			"token", token[:8]+"...")
		return apierrors.HandleBadRequestError(c, "Confirmation link not valid for this channel")
	}

	err = ctr.s.ConfirmManagerChangeRequest(ctx, tokenText)
	if err != nil {
		logger.Error("Failed to confirm manager change request",
			"channelID", channelID,
			"token", token[:8]+"...",
			"error", err.Error())
		return apierrors.HandleDatabaseError(c, err)
	}

	logger.Info("Manager change request confirmed successfully",
		"channelID", channelID,
		"requestID", request.ID,
		"changeType", request.ChangeType.Int16,
		"token", token[:8]+"...")

	response := ManagerChangeConfirmationResponse{
		Status:  "success",
		Message: "Manager change request confirmed successfully",
		Data: ManagerChangeConfirmationData{
			ChannelID:   request.ChannelID,
			ChannelName: request.ChannelName,
			RequestID:   request.ID.Int32,
			ChangeType:  getChangeTypeString(request.ChangeType.Int16),
			Status:      "confirmed",
		},
	}

	return c.JSON(http.StatusOK, response)
}
