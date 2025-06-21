package helper

import (
	"context"
	"fmt"
	"strings"

	"github.com/undernetirc/cservice-api/internal/config"
	"github.com/undernetirc/cservice-api/models"
)

// EmailLockValidator handles email lock validation
type EmailLockValidator struct {
	db models.Querier
}

// NewEmailLockValidator creates a new email lock validator
func NewEmailLockValidator(db models.Querier) *EmailLockValidator {
	return &EmailLockValidator{
		db: db,
	}
}

// IsEmailLocked checks if an email address is locked for channel registration
// This matches the PHP is_email_locked($LOCK_REGPROC, $email) function
func (v *EmailLockValidator) IsEmailLocked(_ context.Context, email string) (bool, error) {
	if email == "" {
		return false, nil
	}

	// Get the list of locked email domains/patterns from config
	lockedDomains := config.ServiceChannelRegLockedEmailDomains.GetStringSlice()
	lockedPatterns := config.ServiceChannelRegLockedEmailPatterns.GetStringSlice()

	normalizedEmail := strings.ToLower(strings.TrimSpace(email))

	// Check against locked domains
	for _, domain := range lockedDomains {
		if strings.HasSuffix(normalizedEmail, "@"+strings.ToLower(domain)) {
			return true, nil
		}
	}

	// Check against locked patterns
	for _, pattern := range lockedPatterns {
		if strings.Contains(normalizedEmail, strings.ToLower(pattern)) {
			return true, nil
		}
	}

	// Additional checks can be added here for database-based email locks
	// if needed in the future

	return false, nil
}

// ValidateUserEmailNotLocked validates that a user's email is not locked
func (v *EmailLockValidator) ValidateUserEmailNotLocked(ctx context.Context, userID int32) error {
	// Get user information including email using the efficient GetUser function
	user, err := v.db.GetUser(ctx, models.GetUserParams{
		ID: userID,
	})
	if err != nil {
		return &ValidationError{
			Code:    "DATABASE_ERROR",
			Message: "Failed to check user email",
			Details: map[string]interface{}{
				"error": err.Error(),
			},
		}
	}

	if !user.Email.Valid {
		return &ValidationError{
			Code:    "INVALID_EMAIL",
			Message: "User email is not available",
			Details: map[string]interface{}{
				"user_id": userID,
			},
		}
	}

	isLocked, err := v.IsEmailLocked(ctx, user.Email.String)
	if err != nil {
		return &ValidationError{
			Code:    "EMAIL_VALIDATION_ERROR",
			Message: "Failed to validate email lock status",
			Details: map[string]interface{}{
				"error": err.Error(),
			},
		}
	}

	if isLocked {
		return &ValidationError{
			Code:    "EMAIL_LOCKED",
			Message: "Your email address is not allowed for channel registration",
			Details: map[string]interface{}{
				"email": user.Email.String,
			},
		}
	}

	return nil
}

// ValidateSupporterEmailNotLocked validates that a supporter's email is not locked
func (v *EmailLockValidator) ValidateSupporterEmailNotLocked(ctx context.Context, supporterUsername string) error {
	// Get supporter information including email using the efficient GetUser function
	supporter, err := v.db.GetUser(ctx, models.GetUserParams{
		Username: supporterUsername,
	})
	if err != nil {
		return &ValidationError{
			Code:    "DATABASE_ERROR",
			Message: "Failed to check supporter email",
			Details: map[string]interface{}{
				"supporter": supporterUsername,
				"error":     err.Error(),
			},
		}
	}

	if !supporter.Email.Valid {
		return &ValidationError{
			Code:    "INVALID_EMAIL",
			Message: "Supporter email is not available",
			Details: map[string]interface{}{
				"supporter": supporterUsername,
			},
		}
	}

	isLocked, err := v.IsEmailLocked(ctx, supporter.Email.String)
	if err != nil {
		return &ValidationError{
			Code:    "EMAIL_VALIDATION_ERROR",
			Message: "Failed to validate supporter email lock status",
			Details: map[string]interface{}{
				"supporter": supporterUsername,
				"error":     err.Error(),
			},
		}
	}

	if isLocked {
		return &ValidationError{
			Code:    "SUPPORTER_EMAIL_LOCKED",
			Message: "Supporter's email address is not allowed for channel registration",
			Details: map[string]interface{}{
				"supporter": supporterUsername,
				"email":     supporter.Email.String,
			},
		}
	}

	return nil
}

// ValidateUserEmailLock checks if the user's email is locked
func (v *EmailLockValidator) ValidateUserEmailLock(ctx context.Context, userID int32) error {
	// Get user information including email using the efficient GetUser function
	user, err := v.db.GetUser(ctx, models.GetUserParams{
		ID: userID,
	})
	if err != nil {
		return fmt.Errorf("failed to get user email: %w", err)
	}

	// Check if email is valid
	if !user.Email.Valid {
		return fmt.Errorf("user has no email address")
	}

	email := user.Email.String
	if IsEmailLocked(email) {
		return fmt.Errorf("email domain/pattern is locked: %s", email)
	}

	return nil
}

// ValidateSupporterEmailLock checks if a supporter's email is locked
func (v *EmailLockValidator) ValidateSupporterEmailLock(ctx context.Context, supporterUsername string) error {
	// Get supporter information including email using the efficient GetUser function
	user, err := v.db.GetUser(ctx, models.GetUserParams{
		Username: supporterUsername,
	})
	if err != nil {
		return fmt.Errorf("failed to get supporter email: %w", err)
	}

	// Check if email is valid
	if !user.Email.Valid {
		return fmt.Errorf("supporter %s has no email address", supporterUsername)
	}

	email := user.Email.String
	if IsEmailLocked(email) {
		return fmt.Errorf("supporter %s email domain/pattern is locked: %s", supporterUsername, email)
	}

	return nil
}
