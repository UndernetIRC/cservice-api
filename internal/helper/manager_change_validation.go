// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

// Package helper provides helper functions for manager change validation
package helper

import (
	"context"
	"fmt"
	"time"

	apierrors "github.com/undernetirc/cservice-api/internal/errors"
	"github.com/undernetirc/cservice-api/models"
)

// ManagerChangeValidator provides validation for manager change requests
type ManagerChangeValidator struct {
	db models.ServiceInterface
}

// NewManagerChangeValidator creates a new manager change validator
func NewManagerChangeValidator(db models.ServiceInterface) *ManagerChangeValidator {
	return &ManagerChangeValidator{
		db: db,
	}
}

// ValidateManagerChangeBusinessRules performs comprehensive validation of a manager change request
func (v *ManagerChangeValidator) ValidateManagerChangeBusinessRules(
	ctx context.Context,
	channelID int32,
	userID int32,
	newManagerUsername string,
	changeType string,
) error {
	// Check user has level 500 access on channel
	_, err := v.db.CheckUserChannelOwnership(ctx, userID, channelID)
	if err != nil {
		return &ValidationError{
			Code:    apierrors.ErrCodeForbidden,
			Message: "User is not channel owner",
			Details: map[string]interface{}{
				"error": err.Error(),
			},
		}
	}

	channel, err := v.db.CheckChannelExistsAndRegistered(ctx, channelID)
	if err != nil {
		return &ValidationError{
			Code:    apierrors.ErrCodeNotFound,
			Message: "Channel not found or not registered",
			Details: map[string]interface{}{
				"error": err.Error(),
			},
		}
	}

	channelAge := time.Now().Unix() - int64(channel.RegisteredTs.Int32)
	if channelAge < 86400*90 { // 90 days in seconds
		return &ValidationError{
			Code:    apierrors.ErrCodeForbidden,
			Message: "Channel must be at least 90 days old for manager changes",
		}
	}

	newManager, err := v.db.GetUser(ctx, models.GetUserParams{
		Username: newManagerUsername,
	})
	if err != nil {
		return &ValidationError{
			Code:    apierrors.ErrCodeNotFound,
			Message: "New manager username not found",
			Details: map[string]interface{}{
				"error": err.Error(),
			},
		}
	}

	// Check new manager has level 499 access on channel
	_, err = v.db.CheckNewManagerChannelAccess(ctx, channelID, newManager.ID)
	if err != nil {
		return &ValidationError{
			Code:    apierrors.ErrCodeForbidden,
			Message: "New manager must have level 499 access on the channel and be active in the last 20 days",
			Details: map[string]interface{}{
				"error": err.Error(),
			},
		}
	}

	// Check new manager account age requirements
	accountAge := time.Now().Unix() - int64(newManager.SignupTs.Int32)
	if changeType == "permanent" && accountAge < 86400*90 { // 90 days for permanent
		return &ValidationError{
			Code:    apierrors.ErrCodeForbidden,
			Message: "New manager account must be at least 90 days old for permanent changes",
		}
	}
	if changeType == "temporary" && accountAge < 86400*30 { // 30 days for temporary
		return &ValidationError{
			Code:    apierrors.ErrCodeForbidden,
			Message: "New manager account must be at least 30 days old for temporary changes",
		}
	}

	pendingRequests, err := v.db.CheckExistingPendingRequests(ctx, channelID)
	if err != nil {
		return &ValidationError{
			Code:    apierrors.ErrCodeDatabase,
			Message: "Failed to check existing pending requests",
			Details: map[string]interface{}{
				"error": err.Error(),
			},
		}
	}
	if len(pendingRequests) > 0 {
		return &ValidationError{
			Code:    apierrors.ErrCodeConflict,
			Message: "Channel already has a pending manager change request",
		}
	}

	// TODO: this should probably follow the account age on how many registered channels you may own
	if changeType == "permanent" {
		ownsOtherChannels, err := v.db.CheckUserOwnsOtherChannels(ctx, newManager.ID)
		if err != nil {
			return &ValidationError{
				Code:    apierrors.ErrCodeDatabase,
				Message: "Failed to check if user owns other channels",
				Details: map[string]interface{}{
					"error": err.Error(),
				},
			}
		}
		if ownsOtherChannels {
			return &ValidationError{
				Code:    apierrors.ErrCodeForbidden,
				Message: "New manager already owns other channels and cannot receive permanent ownership",
			}
		}
	}

	managerCount, err := v.db.CheckChannelSingleManager(ctx, channelID)
	if err != nil {
		return &ValidationError{
			Code:    apierrors.ErrCodeDatabase,
			Message: "Failed to check channel manager count",
			Details: map[string]interface{}{
				"error": err.Error(),
			},
		}
	}
	if managerCount > 1 {
		return &ValidationError{
			Code:    apierrors.ErrCodeForbidden,
			Message: "Channel has multiple managers. Please contact support for special procedures",
		}
	}

	userStatus, err := v.db.CheckUserCooldownStatus(ctx, userID)
	if err != nil {
		return &ValidationError{
			Code:    apierrors.ErrCodeDatabase,
			Message: "Failed to check user cooldown status",
			Details: map[string]interface{}{
				"error": err.Error(),
			},
		}
	}

	// Check verification data is set
	if !userStatus.Verificationdata.Valid || userStatus.Verificationdata.String == "" {
		return &ValidationError{
			Code:    apierrors.ErrCodeForbidden,
			Message: "You need to have verification information set",
		}
	}

	// Check email is set
	if !userStatus.Email.Valid || userStatus.Email.String == "" {
		return &ValidationError{
			Code:    apierrors.ErrCodeForbidden,
			Message: "You need to have your email set",
		}
	}

	// Check cooldown period
	if userStatus.PostForms > 0 {
		currentTime := time.Now().Unix()
		if int64(userStatus.PostForms) > currentTime {
			cooldownEnd := time.Unix(int64(userStatus.PostForms), 0)
			return &ValidationError{
				Code: apierrors.ErrCodeBadRequest,
				Message: fmt.Sprintf(
					"You can submit another form request after %s",
					cooldownEnd.Format("2006-01-02 15:04:05"),
				),
			}
		}
		if userStatus.PostForms == 666 {
			return &ValidationError{
				Code:    apierrors.ErrCodeForbidden,
				Message: "Your account has been locked from submitting forms",
			}
		}
	}

	return nil
}
