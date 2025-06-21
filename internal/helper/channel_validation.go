// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

// Package helper provides helper functions for channel registration validation
package helper

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/undernetirc/cservice-api/internal/config"
	apierrors "github.com/undernetirc/cservice-api/internal/errors"
	"github.com/undernetirc/cservice-api/models"
)

// ValidationError represents a validation error with structured details
type ValidationError struct {
	Code    string      `json:"code"`
	Message string      `json:"message"`
	Details interface{} `json:"details,omitempty"`
}

func (v *ValidationError) Error() string {
	return v.Message
}

// GetCode returns the error code
func (v *ValidationError) GetCode() string {
	return v.Code
}

// GetMessage returns the error message
func (v *ValidationError) GetMessage() string {
	return v.Message
}

// GetDetails returns the error details
func (v *ValidationError) GetDetails() interface{} {
	return v.Details
}

// ChannelRegistrationValidator provides validation for channel registration requests
type ChannelRegistrationValidator struct {
	db        models.Querier
	validator *Validator
}

// NewChannelRegistrationValidator creates a new channel registration validator
func NewChannelRegistrationValidator(db models.Querier, validator *Validator) *ChannelRegistrationValidator {
	return &ChannelRegistrationValidator{
		db:        db,
		validator: validator,
	}
}

// ChannelRegistrationRequest represents the channel registration request structure
// This should match the struct in controllers/channel.go
type ChannelRegistrationRequest struct {
	ChannelName string   `json:"channel_name" validate:"required,startswith=#,max=255"`
	Description string   `json:"description" validate:"required,max=300"`
	Supporters  []string `json:"supporters" validate:"required,min=1"`
}

// AdminBypassInfo contains information about admin bypass actions for audit logging
type AdminBypassInfo struct {
	UserID      int32  `json:"user_id"`
	AdminLevel  int32  `json:"admin_level"`
	BypassType  string `json:"bypass_type"`
	Details     string `json:"details"`
	ChannelName string `json:"channel_name,omitempty"`
}

// ValidateChannelRegistrationRequest performs comprehensive validation of a channel registration request
func (v *ChannelRegistrationValidator) ValidateChannelRegistrationRequest(
	ctx context.Context,
	req *ChannelRegistrationRequest,
	userID int32,
) error {
	// First, perform basic struct validation using validator tags
	if err := v.validator.Validate(req); err != nil {
		return &ValidationError{
			Code:    apierrors.ErrCodeValidation,
			Message: fmt.Sprintf("Basic validation failed: %s", err.Error()),
			Details: map[string]interface{}{
				"validation_errors": err.Error(),
			},
		}
	}

	// Custom channel name validation
	if err := v.validateChannelName(req.ChannelName); err != nil {
		return err
	}

	// Custom description validation
	if err := v.validateDescription(req.Description); err != nil {
		return err
	}

	// Supporter validation
	if err := v.validateSupporters(ctx, req.Supporters, userID); err != nil {
		return err
	}

	return nil
}

// ValidateChannelRegistrationWithAdminBypass performs comprehensive validation with admin bypass capabilities
func (v *ChannelRegistrationValidator) ValidateChannelRegistrationWithAdminBypass(
	ctx context.Context,
	req *ChannelRegistrationRequest,
	userID int32,
	_ int32, // adminLevel - no bypass allowed for basic validation
) ([]AdminBypassInfo, error) {
	var bypasses []AdminBypassInfo

	// First, perform basic struct validation using validator tags (no admin bypass for basic validation)
	if err := v.validator.Validate(req); err != nil {
		return nil, &ValidationError{
			Code:    apierrors.ErrCodeValidation,
			Message: fmt.Sprintf("Basic validation failed: %s", err.Error()),
			Details: map[string]interface{}{
				"validation_errors": err.Error(),
			},
		}
	}

	// Custom channel name validation (no admin bypass)
	if err := v.validateChannelName(req.ChannelName); err != nil {
		return nil, err
	}

	// Custom description validation (no admin bypass)
	if err := v.validateDescription(req.Description); err != nil {
		return nil, err
	}

	// Supporter validation (no admin bypass)
	if err := v.validateSupporters(ctx, req.Supporters, userID); err != nil {
		return nil, err
	}

	return bypasses, nil
}

// ValidateUserNoregStatusWithAdminBypass validates user NOREG status (no admin bypass allowed)
func (v *ChannelRegistrationValidator) ValidateUserNoregStatusWithAdminBypass(
	ctx context.Context,
	userID int32,
	_ int32, // adminLevel - no bypass allowed for user restrictions
) ([]AdminBypassInfo, error) {
	// User restrictions (NOREG flags, fraud flags) apply to ALL users including admins
	return nil, v.ValidateUserNoregStatus(ctx, userID)
}

// ValidateUserChannelLimitsWithAdminBypass validates channel limits with admin bypass for multiple channels
func (v *ChannelRegistrationValidator) ValidateUserChannelLimitsWithAdminBypass(
	ctx context.Context,
	userID int32,
	adminLevel int32,
) ([]AdminBypassInfo, error) {
	var bypasses []AdminBypassInfo

	// Check if multiple channels are disabled and user already has channels
	if !config.ServiceChannelRegAllowMultiple.GetBool() {
		// Get user's current channel count
		userChannels, err := v.db.GetUserChannels(ctx, userID)
		if err != nil {
			return nil, &ValidationError{
				Code:    apierrors.ErrCodeDatabaseError,
				Message: "Failed to check user's existing channels",
				Details: map[string]interface{}{
					"error": err.Error(),
				},
			}
		}

		if len(userChannels) > 0 {
			// Admin level 1+ can bypass multiple channel restrictions
			if adminLevel >= 1 {
				bypasses = append(bypasses, AdminBypassInfo{
					UserID:     userID,
					AdminLevel: adminLevel,
					BypassType: "MULTIPLE_CHANNEL_BYPASS",
					Details:    fmt.Sprintf("Admin bypassed multiple channel restriction (user has %d existing channels)", len(userChannels)),
				})
				return bypasses, nil
			}

			// Non-admin users are blocked
			return nil, &ValidationError{
				Code:    apierrors.ErrCodeChannelLimitExceeded,
				Message: "Multiple channel registrations are currently disabled and you already own a channel",
				Details: map[string]interface{}{
					"existing_channels": len(userChannels),
					"allow_multiple":    false,
				},
			}
		}
	}

	// Perform regular channel limit validation
	if err := v.ValidateUserChannelLimits(ctx, userID); err != nil {
		// Admin level 1+ can bypass general channel limits
		if adminLevel >= 1 {
			bypasses = append(bypasses, AdminBypassInfo{
				UserID:     userID,
				AdminLevel: adminLevel,
				BypassType: "CHANNEL_LIMIT_BYPASS",
				Details:    "Admin bypassed general channel limit restrictions",
			})
			return bypasses, nil
		}
		return nil, err
	}

	return bypasses, nil
}

// ValidatePendingRegistrationsWithAdminBypass validates pending registrations with admin bypass
func (v *ChannelRegistrationValidator) ValidatePendingRegistrationsWithAdminBypass(
	ctx context.Context,
	userID int32,
	adminLevel int32,
) ([]AdminBypassInfo, error) {
	var bypasses []AdminBypassInfo

	// Check for existing pending registrations
	pendingCount, err := v.db.GetUserPendingRegistrations(ctx, pgtype.Int4{Int32: userID, Valid: true})
	if err != nil {
		return nil, &ValidationError{
			Code:    apierrors.ErrCodeDatabaseError,
			Message: "Failed to check pending registrations",
			Details: map[string]interface{}{
				"error": err.Error(),
			},
		}
	}

	if pendingCount > 0 {
		// Admin level 800+ can bypass pending registration restrictions
		if adminLevel >= 800 {
			bypasses = append(bypasses, AdminBypassInfo{
				UserID:     userID,
				AdminLevel: adminLevel,
				BypassType: "PENDING_REGISTRATION_BYPASS",
				Details:    fmt.Sprintf("Admin bypassed pending registration restriction (user has %d pending registrations)", pendingCount),
			})
			return bypasses, nil
		}

		// Non-admin or lower-level admin users are blocked
		return nil, &ValidationError{
			Code:    apierrors.ErrCodePendingExists,
			Message: "You already have a pending channel registration",
			Details: map[string]interface{}{
				"pending_count": pendingCount,
			},
		}
	}

	return bypasses, nil
}

// ValidateChannelNameAvailabilityWithAdminBypass validates channel name availability (no admin bypass)
func (v *ChannelRegistrationValidator) ValidateChannelNameAvailabilityWithAdminBypass(
	ctx context.Context,
	channelName string,
	_ int32, // adminLevel - no bypass allowed for channel name availability
) ([]AdminBypassInfo, error) {
	// Channel name availability cannot be bypassed by admins
	return nil, v.ValidateChannelNameAvailability(ctx, channelName)
}

// ValidateUserIRCActivityWithAdminBypass validates IRC activity requirements (no admin bypass)
func (v *ChannelRegistrationValidator) ValidateUserIRCActivityWithAdminBypass(
	ctx context.Context,
	userID int32,
	_ int32, // adminLevel - no bypass allowed for IRC activity requirements
) ([]AdminBypassInfo, error) {
	// IRC activity requirements cannot be bypassed by admins
	return nil, v.ValidateUserIRCActivity(ctx, userID)
}

// validateChannelName validates IRC channel name format
func (v *ChannelRegistrationValidator) validateChannelName(channelName string) error {
	// Check for empty or whitespace-only channel name
	if strings.TrimSpace(channelName) == "" {
		return &ValidationError{
			Code:    apierrors.ErrCodeInvalidChannelName,
			Message: "Channel name cannot be empty",
			Details: map[string]interface{}{
				"field": "channel_name",
				"rule":  "not_empty",
			},
		}
	}

	// Check minimum length (must be at least 2 characters: # + name)
	if len(channelName) < 2 {
		return &ValidationError{
			Code:    apierrors.ErrCodeInvalidChannelName,
			Message: "Channel name must be at least 2 characters long",
			Details: map[string]interface{}{
				"field":    "channel_name",
				"provided": channelName,
				"rule":     "min_length",
				"minimum":  2,
			},
		}
	}

	if !strings.HasPrefix(channelName, "#") {
		return &ValidationError{
			Code:    apierrors.ErrCodeInvalidChannelName,
			Message: "Channel name must start with '#'",
			Details: map[string]interface{}{
				"field":    "channel_name",
				"provided": channelName,
				"rule":     "must_start_with_hash",
			},
		}
	}

	// Check for invalid IRC channel characters
	// Based on RFC 1459: channels cannot contain space, comma, or control characters
	invalidChars := regexp.MustCompile(`[\s,\x00-\x1F\x7F]`)
	if invalidChars.MatchString(channelName) {
		return &ValidationError{
			Code:    apierrors.ErrCodeInvalidChannelName,
			Message: "Channel name contains invalid characters",
			Details: map[string]interface{}{
				"field":         "channel_name",
				"provided":      channelName,
				"rule":          "no_invalid_chars",
				"invalid_chars": "space, comma, or control characters",
			},
		}
	}

	// Additional IRC-specific invalid characters
	additionalInvalidChars := []string{"*", "?", "!", "@", "$", "%", "+"}
	for _, char := range additionalInvalidChars {
		if strings.Contains(channelName, char) {
			return &ValidationError{
				Code:    apierrors.ErrCodeInvalidChannelName,
				Message: fmt.Sprintf("Channel name cannot contain '%s'", char),
				Details: map[string]interface{}{
					"field":        "channel_name",
					"provided":     channelName,
					"rule":         "no_special_chars",
					"invalid_char": char,
				},
			}
		}
	}

	return nil
}

// validateDescription validates channel description
func (v *ChannelRegistrationValidator) validateDescription(description string) error {
	// Check for empty or whitespace-only description
	if strings.TrimSpace(description) == "" {
		return &ValidationError{
			Code:    apierrors.ErrCodeInvalidDescription,
			Message: "Description cannot be empty or contain only whitespace",
			Details: map[string]interface{}{
				"field": "description",
				"rule":  "not_empty",
			},
		}
	}

	// Check for potentially dangerous content
	dangerousPatterns := []string{
		"<script", "</script>", "javascript:", "onclick=", "onerror=",
		"<iframe", "</iframe>", "<object", "</object>", "<embed", "</embed>",
		"<form", "</form>", "onload=", "onmouseover=", "onfocus=",
	}

	lowerDesc := strings.ToLower(description)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(lowerDesc, pattern) {
			return &ValidationError{
				Code:    apierrors.ErrCodeInvalidDescription,
				Message: "Description contains potentially dangerous content",
				Details: map[string]interface{}{
					"field":            "description",
					"rule":             "no_dangerous_content",
					"detected_pattern": pattern,
				},
			}
		}
	}

	return nil
}

// validateSupporters validates the supporters list
func (v *ChannelRegistrationValidator) validateSupporters(ctx context.Context, supporters []string, userID int32) error {
	// Check minimum number of supporters required
	requiredSupporters := config.ServiceChannelRegRequiredSupporters.GetInt()
	if len(supporters) < requiredSupporters {
		return &ValidationError{
			Code:    apierrors.ErrCodeInsufficientSupporters,
			Message: fmt.Sprintf("Channel registration requires %d supporters", requiredSupporters),
			Details: map[string]interface{}{
				"field":    "supporters",
				"required": requiredSupporters,
				"provided": len(supporters),
			},
		}
	}

	// Get the current user's username to check for self-support
	currentUser, err := v.db.GetUser(ctx, models.GetUserParams{
		ID: userID,
	})
	if err != nil {
		return &ValidationError{
			Code:    apierrors.ErrCodeDatabaseError,
			Message: "Failed to validate user information",
			Details: map[string]interface{}{
				"error": err.Error(),
			},
		}
	}

	// Check for self-support
	currentUsername := strings.ToLower(currentUser.Username)
	for _, supporter := range supporters {
		if strings.EqualFold(supporter, currentUsername) {
			return &ValidationError{
				Code:    apierrors.ErrCodeSelfSupportNotAllowed,
				Message: "You cannot list yourself as a supporter",
				Details: map[string]interface{}{
					"field":    "supporters",
					"username": currentUser.Username,
				},
			}
		}
	}

	// Check for empty or whitespace-only supporter names
	for i, supporter := range supporters {
		if strings.TrimSpace(supporter) == "" {
			return &ValidationError{
				Code:    apierrors.ErrCodeInvalidSupporters,
				Message: "Supporter names cannot be empty or contain only whitespace",
				Details: map[string]interface{}{
					"field":         "supporters",
					"invalid_index": i,
					"invalid_value": supporter,
					"rule":          "not_empty",
				},
			}
		}
	}

	// Check for duplicate supporters
	supporterMap := make(map[string]bool)
	var duplicates []string
	for _, supporter := range supporters {
		normalizedSupporter := strings.ToLower(strings.TrimSpace(supporter))
		if supporterMap[normalizedSupporter] {
			duplicates = append(duplicates, supporter)
		} else {
			supporterMap[normalizedSupporter] = true
		}
	}

	if len(duplicates) > 0 {
		return &ValidationError{
			Code:    apierrors.ErrCodeDuplicateSupporters,
			Message: "Supporters list contains duplicates",
			Details: map[string]interface{}{
				"field":      "supporters",
				"duplicates": duplicates,
			},
		}
	}

	// Efficiently validate all supporters with a single bulk query
	return v.validateAllSupportersEfficiently(ctx, supporters)
}

// validateAllSupportersEfficiently performs all supporter validations with minimal database calls
func (v *ChannelRegistrationValidator) validateAllSupportersEfficiently(ctx context.Context, supporters []string) error {
	minDaysBeforeSupport := config.ServiceChannelRegMinDaysBeforeSupport.GetInt()
	maxConcurrentSupports := config.ServiceChannelRegMaxConcurrentSupports.GetInt()

	// Single query to get all supporter information including age and fraud flag validation
	supporterData, err := v.db.GetSupportersByUsernames(ctx, supporters, int32(minDaysBeforeSupport)) //nolint:gosec // minDaysBeforeSupport is a config value, safe conversion
	if err != nil {
		return &ValidationError{
			Code:    apierrors.ErrCodeDatabaseError,
			Message: "Failed to validate supporters",
			Details: map[string]interface{}{
				"error": err.Error(),
			},
		}
	}

	// Check if all supporters exist
	if len(supporterData) != len(supporters) {
		foundSupporters := make(map[string]bool)
		for _, data := range supporterData {
			foundSupporters[strings.ToLower(data.Username)] = true
		}

		var invalidSupporters []string
		for _, supporter := range supporters {
			if !foundSupporters[strings.ToLower(supporter)] {
				invalidSupporters = append(invalidSupporters, supporter)
			}
		}

		return &ValidationError{
			Code:    apierrors.ErrCodeInvalidSupporters,
			Message: "One or more supporters do not exist",
			Details: map[string]interface{}{
				"field":              "supporters",
				"invalid_supporters": invalidSupporters,
			},
		}
	}

	// Validate each supporter's eligibility
	var tooNewSupporters []string
	var fraudSupporters []string
	var lockedEmailSupporters []string

	for _, data := range supporterData {
		// Check age requirement
		if !data.IsOldEnough {
			tooNewSupporters = append(tooNewSupporters, data.Username)
		}

		// Check fraud flag
		if data.HasFraudFlag {
			fraudSupporters = append(fraudSupporters, data.Username)
		}

		// Check email lock
		if IsEmailLocked(data.Email.String) {
			lockedEmailSupporters = append(lockedEmailSupporters, data.Username)
		}
	}

	// Report age validation errors
	if len(tooNewSupporters) > 0 {
		return &ValidationError{
			Code:    apierrors.ErrCodeSupportersTooNew,
			Message: fmt.Sprintf("One or more supporters are too newly created (less than %d days)", minDaysBeforeSupport),
			Details: map[string]interface{}{
				"field":              "supporters",
				"min_days_required":  minDaysBeforeSupport,
				"invalid_supporters": tooNewSupporters,
			},
		}
	}

	// Report fraud flag errors
	if len(fraudSupporters) > 0 {
		return &ValidationError{
			Code:    apierrors.ErrCodeSupportersRestricted,
			Message: "One or more supporters have fraud restrictions",
			Details: map[string]interface{}{
				"field":              "supporters",
				"invalid_supporters": fraudSupporters,
				"restriction_type":   "fraud_flag",
			},
		}
	}

	// Report email lock errors
	if len(lockedEmailSupporters) > 0 {
		return &ValidationError{
			Code:    apierrors.ErrCodeSupportersEmailLocked,
			Message: "One or more supporters are using invalid email addresses",
			Details: map[string]interface{}{
				"field":              "supporters",
				"invalid_supporters": lockedEmailSupporters,
			},
		}
	}

	// Single query to check NOREG status for all supporters
	noregResults, err := v.db.CheckMultipleSupportersNoregStatus(ctx, supporters)
	if err != nil {
		return &ValidationError{
			Code:    apierrors.ErrCodeDatabaseError,
			Message: "Failed to check supporter NOREG status",
			Details: map[string]interface{}{
				"error": err.Error(),
			},
		}
	}

	var noregSupporters []string
	for _, result := range noregResults {
		if result.IsNoreg {
			if username, ok := result.Username.(string); ok {
				noregSupporters = append(noregSupporters, username)
			}
		}
	}

	if len(noregSupporters) > 0 {
		return &ValidationError{
			Code:    apierrors.ErrCodeSupportersRestricted,
			Message: "One or more supporters are in NOREG",
			Details: map[string]interface{}{
				"field":              "supporters",
				"invalid_supporters": noregSupporters,
				"restriction_type":   "noreg",
			},
		}
	}

	// Single query to check concurrent support limits for all supporters
	concurrentResults, err := v.db.CheckMultipleSupportersConcurrentSupports(ctx, supporters, int32(maxConcurrentSupports)) //nolint:gosec // maxConcurrentSupports is a config value, safe conversion
	if err != nil {
		return &ValidationError{
			Code:    apierrors.ErrCodeDatabaseError,
			Message: "Failed to check supporter concurrent support limits",
			Details: map[string]interface{}{
				"error": err.Error(),
			},
		}
	}

	var overLimitSupporters []string
	for _, result := range concurrentResults {
		if result.ExceedsLimit {
			overLimitSupporters = append(overLimitSupporters, result.Username)
		}
	}

	if len(overLimitSupporters) > 0 {
		return &ValidationError{
			Code:    apierrors.ErrCodeSupportersOverLimit,
			Message: fmt.Sprintf("One or more supporters are supporting too many channels (limit: %d)", maxConcurrentSupports),
			Details: map[string]interface{}{
				"field":              "supporters",
				"invalid_supporters": overLimitSupporters,
				"max_concurrent":     maxConcurrentSupports,
			},
		}
	}

	return nil
}

// IsEmailLocked is a simple wrapper around the email validation logic
// This matches the PHP is_email_locked() function behavior
func IsEmailLocked(email string) bool {
	if email == "" {
		return false
	}

	// Get the list of locked email domains/patterns from config
	lockedDomains := config.ServiceChannelRegLockedEmailDomains.GetStringSlice()
	lockedPatterns := config.ServiceChannelRegLockedEmailPatterns.GetStringSlice()

	normalizedEmail := strings.ToLower(strings.TrimSpace(email))

	// Check against locked domains
	for _, domain := range lockedDomains {
		if strings.HasSuffix(normalizedEmail, "@"+strings.ToLower(domain)) {
			return true
		}
	}

	// Check against locked patterns
	for _, pattern := range lockedPatterns {
		if strings.Contains(normalizedEmail, strings.ToLower(pattern)) {
			return true
		}
	}

	return false
}

// ValidateUserChannelLimits validates if the user can register another channel
func (v *ChannelRegistrationValidator) ValidateUserChannelLimits(ctx context.Context, userID int32) error {
	// Check if channel registration is enabled
	if !config.ServiceChannelRegEnabled.GetBool() {
		return &ValidationError{
			Code:    apierrors.ErrCodeRegistrationsDisabled,
			Message: "Channel registration is currently disabled",
			Details: map[string]interface{}{
				"feature": "channel_registration",
			},
		}
	}

	// Get current channel count for the user
	channelCount, err := v.db.GetUserChannelCount(ctx, userID)
	if err != nil {
		return &ValidationError{
			Code:    apierrors.ErrCodeDatabaseError,
			Message: "Failed to check user channel count",
			Details: map[string]interface{}{
				"error": err.Error(),
			},
		}
	}

	// Get user's channel limit based on their flags
	userLimits, err := v.db.GetUserChannelLimit(ctx, models.GetUserChannelLimitParams{
		ID:      userID,
		Column2: SafeInt32(config.ServiceChannelRegMaxChannelsAdmin.GetInt()),
		Column3: SafeInt32(config.ServiceChannelRegMaxChannelsSupporter.GetInt()),
		Column4: SafeInt32(config.ServiceChannelRegMaxChannelsRegular.GetInt()),
	})
	if err != nil {
		return &ValidationError{
			Code:    apierrors.ErrCodeDatabaseError,
			Message: "Failed to check user channel limits",
			Details: map[string]interface{}{
				"error": err.Error(),
			},
		}
	}

	// Check if user has reached their limit
	if channelCount >= int64(userLimits) {
		return &ValidationError{
			Code:    apierrors.ErrCodeChannelLimitReached,
			Message: "You have reached your channel registration limit",
			Details: map[string]interface{}{
				"current_count": channelCount,
				"limit":         userLimits,
			},
		}
	}

	// Check cooldown period if not allowing multiple registrations
	if !config.ServiceChannelRegAllowMultiple.GetBool() && channelCount > 0 {
		lastRegistration, err := v.db.GetLastChannelRegistration(ctx, userID)
		if err == nil && lastRegistration.Valid {
			cooldownHours := config.ServiceChannelRegCooldownHours.GetInt()
			cooldownDuration := time.Duration(cooldownHours) * time.Hour
			lastRegTime := time.Unix(int64(lastRegistration.Int32), 0)

			if time.Since(lastRegTime) < cooldownDuration {
				nextAllowed := lastRegTime.Add(cooldownDuration)
				return &ValidationError{
					Code:    apierrors.ErrCodeCooldownPeriod,
					Message: "You must wait before registering another channel",
					Details: map[string]interface{}{
						"cooldown_hours":    cooldownHours,
						"last_registration": lastRegTime.Unix(),
						"next_allowed":      nextAllowed.Unix(),
						"wait_hours":        int(time.Until(nextAllowed).Hours()),
					},
				}
			}
		}
	}

	return nil
}

// ValidateUserIRCActivity validates if the user meets IRC activity requirements
func (v *ChannelRegistrationValidator) ValidateUserIRCActivity(ctx context.Context, userID int32) error {
	maxIdleHours := config.ServiceChannelRegIrcIdleHours.GetInt()
	if maxIdleHours <= 0 {
		// IRC activity check is disabled
		return nil
	}

	// Get user information including last seen timestamp
	user, err := v.db.GetUser(ctx, models.GetUserParams{
		ID: userID,
	})
	if err != nil {
		return &ValidationError{
			Code:    apierrors.ErrCodeDatabaseError,
			Message: "Failed to check IRC activity",
			Details: map[string]interface{}{
				"error": err.Error(),
			},
		}
	}

	lastSeen := user.LastSeen

	if !lastSeen.Valid {
		return &ValidationError{
			Code:    apierrors.ErrCodeInactiveUser,
			Message: "IRC activity data not available",
			Details: map[string]interface{}{
				"required_activity_hours": maxIdleHours,
			},
		}
	}

	lastSeenTime := time.Unix(int64(lastSeen.Int32), 0)
	maxIdleDuration := time.Duration(maxIdleHours) * time.Hour

	if time.Since(lastSeenTime) > maxIdleDuration {
		return &ValidationError{
			Code:    apierrors.ErrCodeInactiveUser,
			Message: "User has been inactive on IRC for too long",
			Details: map[string]interface{}{
				"last_seen":             lastSeenTime.Unix(),
				"max_idle_hours":        maxIdleHours,
				"hours_since_last_seen": int(time.Since(lastSeenTime).Hours()),
			},
		}
	}

	return nil
}

// ValidateChannelNameAvailability checks if the channel name is available
func (v *ChannelRegistrationValidator) ValidateChannelNameAvailability(ctx context.Context, channelName string) error {
	// Check if channel name already exists
	_, err := v.db.CheckChannelNameExists(ctx, channelName)
	if err == nil {
		// Channel name exists
		return &ValidationError{
			Code:    apierrors.ErrCodeChannelAlreadyExists,
			Message: "Channel name is already registered",
			Details: map[string]interface{}{
				"field":        "channel_name",
				"channel_name": channelName,
			},
		}
	}

	// Check if there's a pending registration for this name
	// Note: This would require a query to check pending registrations
	// For now, we'll assume the error from CheckChannelNameExists indicates it's available

	return nil
}

// ValidateUserNoregStatus checks if the user has NOREG restrictions
func (v *ChannelRegistrationValidator) ValidateUserNoregStatus(ctx context.Context, userID int32) error {
	// Get user information to check username
	user, err := v.db.GetUser(ctx, models.GetUserParams{
		ID: userID,
	})
	if err != nil {
		return &ValidationError{
			Code:    apierrors.ErrCodeDatabaseError,
			Message: "Failed to check user information",
			Details: map[string]interface{}{
				"error": err.Error(),
			},
		}
	}

	// Check if user has NOREG status
	hasNoreg, err := v.db.CheckUserNoregStatus(ctx, user.Username)
	if err != nil {
		return &ValidationError{
			Code:    apierrors.ErrCodeDatabaseError,
			Message: "Failed to check NOREG status",
			Details: map[string]interface{}{
				"error": err.Error(),
			},
		}
	}

	if hasNoreg {
		return &ValidationError{
			Code:    apierrors.ErrCodeUserRestricted,
			Message: "User is restricted from registering channels",
			Details: map[string]interface{}{
				"restriction_type": "NOREG",
				"username":         user.Username,
			},
		}
	}

	return nil
}
