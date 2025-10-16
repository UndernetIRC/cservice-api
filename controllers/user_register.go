package controllers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/undernetirc/cservice-api/db"
	"github.com/undernetirc/cservice-api/internal/checks"
	"github.com/undernetirc/cservice-api/internal/config"
	apierrors "github.com/undernetirc/cservice-api/internal/errors"
	"github.com/undernetirc/cservice-api/internal/helper"
	"github.com/undernetirc/cservice-api/internal/mail"
	"github.com/undernetirc/cservice-api/internal/tracing"
	"github.com/undernetirc/cservice-api/models"
)

// UserRegisterController is the controller for the authentication routes
type UserRegisterController struct {
	s    models.ServiceInterface
	pool PoolInterface
}

// NewUserRegisterController returns a new UserRegisterController
func NewUserRegisterController(s models.ServiceInterface, pool PoolInterface) *UserRegisterController {
	return &UserRegisterController{s: s, pool: pool}
}

// RegisterRequest is the request body for the register route
type UserRegisterRequest struct {
	Username        string `json:"username"         validate:"required,min=2,max=12"     extensions:"x-order=0"`
	Password        string `json:"password"         validate:"required,min=10,max=72"    extensions:"x-order=1"`
	ConfirmPassword string `json:"confirm_password" validate:"required,eqfield=Password" extensions:"x-order=2"`
	Email           string `json:"email"            validate:"required,email"            extensions:"x-order=3"`
	AUP             bool   `json:"aup"              validate:"required,eq=true"          extensions:"x-order=4"`
	COPPA           bool   `json:"coppa"            validate:"required,eq=true"          extensions:"x-order=5"`
}

// UserRegister example
// @Summary Register
// @Description Creates a new user account.
// @Tags auth
// @Accept json
// @Produce json
// @Param data body UserRegisterRequest true "Register request"
// @Success 201 "User created"
// @Failure 400 {object} errors.ErrorResponse "Bad request"
// @Failure 500 {object} errors.ErrorResponse "Internal server error"
// @Router /register [post]
func (ctr *UserRegisterController) UserRegister(c echo.Context) error {
	logger := helper.GetRequestLogger(c)

	req := new(UserRegisterRequest)

	if err := c.Bind(req); err != nil {
		return apierrors.HandleBadRequestError(c, "Invalid request format")
	}

	if err := c.Validate(req); err != nil {
		return apierrors.HandleValidationError(c, err)
	}

	// Start tracing for the entire user registration operation
	err := tracing.TraceUserRegistration(c.Request().Context(), req.Username, req.Email, "complete_registration", func(ctx context.Context) error {
		// Trace the validation stage
		err := tracing.TraceOperation(ctx, "validate_user_credentials", func(ctx context.Context) error {
			// Add detailed attributes for validation stage
			span := trace.SpanFromContext(ctx)

			// Extract email domain safely
			emailDomain := "unknown"
			if emailParts := strings.Split(req.Email, "@"); len(emailParts) > 1 {
				emailDomain = emailParts[1]
			}

			span.SetAttributes(
				attribute.String("validation.username", req.Username),
				attribute.String("validation.email_domain", emailDomain),
				attribute.String("validation.client_ip", c.RealIP()),
				attribute.String("validation.user_agent", c.Request().UserAgent()),
			)

			// Check if the username or email is already taken
			err := checks.User.IsRegistered(req.Username, req.Email)
			if err != nil && !errors.Is(err, checks.ErrUsernameExists) &&
				!errors.Is(err, checks.ErrEmailExists) {
				logger.Error("Error during user registration check",
					"username", req.Username,
					"email", req.Email,
					"error", err.Error())
				span.SetAttributes(attribute.String("validation.error_type", "database_error"))
				return apierrors.HandleInternalError(c, err, "Failed to check user registration status")
			} else if err != nil {
				logger.Warn("Registration attempt with existing credentials",
					"username", req.Username,
					"email", req.Email,
					"error", err.Error())
				if errors.Is(err, checks.ErrUsernameExists) {
					span.SetAttributes(attribute.String("validation.conflict_type", "username_exists"))
				} else if errors.Is(err, checks.ErrEmailExists) {
					span.SetAttributes(attribute.String("validation.conflict_type", "email_exists"))
				}
				return apierrors.HandleConflictError(c, err.Error())
			}
			span.SetAttributes(attribute.Bool("validation.credentials_available", true))
			return nil
		})
		if err != nil {
			return err
		}

		// Trace the pending user creation stage
		var cookie string
		err = tracing.TraceOperation(ctx, "create_pending_user", func(ctx context.Context) error {
			// Add detailed attributes for pending user creation
			span := trace.SpanFromContext(ctx)
			expirationHours := config.ServicePendingUserExpirationHours.GetInt64()
			expirationTime := time.Now().Add(time.Duration(expirationHours) * time.Hour)

			// Extract email domain safely
			emailDomain := "unknown"
			if emailParts := strings.Split(req.Email, "@"); len(emailParts) > 1 {
				emailDomain = emailParts[1]
			}

			span.SetAttributes(
				attribute.String("pending_user.username", req.Username),
				attribute.String("pending_user.email_domain", emailDomain),
				attribute.Int64("pending_user.expiration_hours", expirationHours),
				attribute.String("pending_user.expiration_time", expirationTime.Format(time.RFC3339)),
				attribute.String("pending_user.client_ip", c.RealIP()),
				attribute.Int("pending_user.language_id", 1),
				attribute.Int("pending_user.password_length", len(req.Password)),
			)

			// Create the pending user
			cookie = helper.GenerateSecureToken(32)
			user := new(models.CreatePendingUserParams)
			user.Username = db.NewString(req.Username)
			user.Email = db.NewString(req.Email)
			user.Cookie = db.NewString(cookie)
			user.Language = db.NewInt4(1)
			user.PosterIp = db.NewString(c.RealIP())
			user.Expire = db.NewInt4(expirationTime.Unix())

			span.SetAttributes(
				attribute.String("pending_user.cookie_length", fmt.Sprintf("%d", len(cookie))),
				attribute.String("pending_user.cookie_prefix", cookie[:8]+"..."),
			)

			if err := user.Password.Set(req.Password); err != nil {
				logger.Error("Failed to hash password during registration",
					"username", req.Username,
					"error", err.Error())
				span.SetAttributes(attribute.String("pending_user.password_hash_error", err.Error()))
				return apierrors.HandleInternalError(c, err, "Failed to process password")
			}

			span.SetAttributes(attribute.Bool("pending_user.password_hashed", true))

			if _, err = ctr.s.CreatePendingUser(ctx, *user); err != nil {
				logger.Error("Failed to create pending user",
					"username", req.Username,
					"email", req.Email,
					"error", err.Error())
				span.SetAttributes(attribute.String("pending_user.database_error", err.Error()))
				return apierrors.HandleDatabaseError(c, err)
			}

			span.SetAttributes(attribute.Bool("pending_user.created", true))
			return nil
		})
		if err != nil {
			return err
		}

		// Trace the email sending stage
		err = tracing.TraceOperation(ctx, "send_activation_email", func(ctx context.Context) error {
			// Add detailed attributes for email sending
			span := trace.SpanFromContext(ctx)
			mailEnabled := config.ServiceMailEnabled.GetBool()
			baseURL := config.ServiceBaseURL.GetString()

			// Extract email domain safely
			emailDomain := "unknown"
			if emailParts := strings.Split(req.Email, "@"); len(emailParts) > 1 {
				emailDomain = emailParts[1]
			}

			span.SetAttributes(
				attribute.Bool("email.service_enabled", mailEnabled),
				attribute.String("email.recipient_domain", emailDomain),
				attribute.String("email.template", "registration"),
				attribute.String("email.subject", "Activate your UnderNET CService account"),
				attribute.String("email.base_url", baseURL),
				attribute.Int("email.template_year", time.Now().Year()),
			)

			// Only send email if mail service is enabled
			if mailEnabled {
				// Generate the activation URL with the cookie token
				activationURL := fmt.Sprintf("%s/activate?token=%s", baseURL, cookie)

				span.SetAttributes(
					attribute.String("email.activation_url_length", fmt.Sprintf("%d", len(activationURL))),
					attribute.String("email.token_prefix", cookie[:8]+"..."),
				)

				// Define template data for the registration email
				templateData := map[string]any{
					"Username":      req.Username,
					"ActivationURL": activationURL,
					"Year":          time.Now().Year(),
				}
				m := mail.NewMail(req.Email, "Activate your UnderNET CService account", "registration", templateData)

				if err := m.Send(); err != nil {
					logger.Error("Failed to send registration email",
						"username", req.Username,
						"email", req.Email,
						"error", err.Error())
					span.SetAttributes(
						attribute.Bool("email.sent", false),
						attribute.String("email.error", err.Error()),
					)
					return err
				}
				logger.Info("Registration email sent successfully",
					"username", req.Username,
					"email", req.Email)
				span.SetAttributes(attribute.Bool("email.sent", true))
			} else {
				logger.Info("Mail service disabled, skipping registration email")
				span.SetAttributes(attribute.String("email.skip_reason", "service_disabled"))
			}
			return nil
		})
		if err != nil {
			// Don't fail the registration if email sending fails
			logger.Error("Email sending failed but continuing with registration",
				"username", req.Username,
				"email", req.Email,
				"error", err.Error())
		}

		logger.Info("User registration initiated successfully",
			"username", req.Username,
			"email", req.Email,
			"ip", c.RealIP())

		return c.NoContent(http.StatusCreated)
	})

	// If the error is ErrResponseSent, the response has already been sent
	// Return nil to prevent Echo from trying to send another response
	if errors.Is(err, apierrors.ErrResponseSent) {
		return nil
	}
	return err
}

// UserActivateRequest is the request body for the activate endpoint
type UserRegisterActivateRequest struct {
	Token string `json:"token" validate:"required" extensions:"x-order=0"`
}

// UserActivateAccountResponse is the response sent to a client upon successful account activation
type UserRegisterActivateResponse struct {
	Username string `json:"username" extensions:"x-order=0"`
	Email    string `json:"email"    extensions:"x-order=1"`
}

// UserActivateAccount godoc
// @Summary Activate user account
// @Description Activates a user account using the provided token.
// @Tags auth
// @Accept json
// @Produce json
// @Param data body UserRegisterActivateRequest true "Activate account request"
// @Success 200 {object} UserRegisterActivateResponse
// @Failure 400 {object} errors.ErrorResponse "Bad request"
// @Failure 401 {object} errors.ErrorResponse "Unauthorized"
// @Failure 404 {object} errors.ErrorResponse "Not found"
// @Failure 500 {object} errors.ErrorResponse "Internal server error"
// @Router /activate [post]
func (ctr *UserRegisterController) UserActivateAccount(c echo.Context) error {
	logger := helper.GetRequestLogger(c)

	req := new(UserRegisterActivateRequest)

	if err := c.Bind(req); err != nil {
		return apierrors.HandleBadRequestError(c, "Invalid request format")
	}

	if err := c.Validate(req); err != nil {
		return apierrors.HandleValidationError(c, err)
	}

	// Start tracing for the entire user activation operation
	err := tracing.TraceUserActivation(c.Request().Context(), "", req.Token, func(ctx context.Context) error {
		// Trace the token validation stage
		var pendingUser models.Pendinguser
		err := tracing.TraceOperation(ctx, "validate_activation_token", func(ctx context.Context) error {
			// Add detailed attributes for token validation
			span := trace.SpanFromContext(ctx)
			span.SetAttributes(
				attribute.String("activation.token_prefix", req.Token[:8]+"..."),
				attribute.Int("activation.token_length", len(req.Token)),
				attribute.String("activation.client_ip", c.RealIP()),
				attribute.String("activation.user_agent", c.Request().UserAgent()),
			)

			var err error
			pendingUser, err = ctr.s.GetPendingUserByCookie(ctx, db.NewString(req.Token))
			if err != nil {
				logger.Warn("Account activation attempt with invalid token",
					"token", req.Token,
					"error", err.Error())
				span.SetAttributes(
					attribute.Bool("activation.token_found", false),
					attribute.String("activation.lookup_error", err.Error()),
				)
				return apierrors.HandleNotFoundError(c, "User")
			}

			// Extract email domain safely
			emailDomain := "unknown"
			if emailParts := strings.Split(pendingUser.Email.String, "@"); len(emailParts) > 1 {
				emailDomain = emailParts[1]
			}

			span.SetAttributes(
				attribute.Bool("activation.token_found", true),
				attribute.String("activation.username", pendingUser.Username.String),
				attribute.String("activation.email_domain", emailDomain),
				attribute.Int64("activation.expiration_timestamp", int64(pendingUser.Expire.Int32)),
			)

			// Check if the pending user record has expired
			currentTime := time.Now().Unix()
			timeUntilExpiry := int64(pendingUser.Expire.Int32) - currentTime
			span.SetAttributes(
				attribute.Int64("activation.current_timestamp", currentTime),
				attribute.Int64("activation.time_until_expiry_seconds", timeUntilExpiry),
				attribute.Bool("activation.is_expired", timeUntilExpiry <= 0),
			)

			if currentTime > int64(pendingUser.Expire.Int32) {
				err := ctr.s.DeletePendingUserByCookie(ctx, pendingUser.Cookie)
				if err != nil {
					logger.Error("Failed to delete expired pending user",
						"username", pendingUser.Username.String,
						"error", err.Error())
					span.SetAttributes(attribute.String("activation.cleanup_error", err.Error()))
				} else {
					span.SetAttributes(attribute.Bool("activation.expired_record_cleaned", true))
				}
				logger.Warn("Account activation attempted with expired token",
					"username", pendingUser.Username.String,
					"token", req.Token)
				return apierrors.HandleUnauthorizedError(c, "Activation token has expired")
			}

			span.SetAttributes(attribute.Bool("activation.token_valid", true))
			return nil
		})
		if err != nil {
			return err
		}

		// Trace the database transaction stage
		var resp UserRegisterActivateResponse
		err = tracing.TraceOperation(ctx, "create_user_transaction", func(ctx context.Context) error {
			// Start transaction
			tx, err := ctr.pool.Begin(ctx)
			if err != nil {
				logger.Error("Failed to start database transaction for activation",
					"username", pendingUser.Username.String,
					"error", err.Error())
				return apierrors.HandleDatabaseError(c, err)
			}
			defer func() {
				if rollbackErr := tx.Rollback(ctx); rollbackErr != nil {
					logger.Error("Failed to rollback transaction",
						"error", rollbackErr.Error())
				}
			}()

			qtx := ctr.s.WithTx(tx)

			// Create the user in the main users table
			createUserParams := models.CreateUserParams{
				Username:   pendingUser.Username.String,
				Password:   pendingUser.Password,
				Email:      pendingUser.Email,
				LanguageID: pendingUser.Language,
				SignupTs:   db.NewInt4(time.Now().UTC().Unix()),
				SignupIp:   db.NewString(c.RealIP()),
				Maxlogins:  db.NewInt4(1),
			}
			newUser, err := qtx.CreateUser(ctx, createUserParams)
			if err != nil {
				logger.Error("Failed to create user from pending user",
					"username", pendingUser.Username.String,
					"error", err.Error())
				return apierrors.HandleDatabaseError(c, err)
			}

			// Delete the pending user record
			err = qtx.DeletePendingUserByCookie(ctx, pendingUser.Cookie)
			if err != nil {
				logger.Error("Failed to delete pending user after activation",
					"username", pendingUser.Username.String,
					"userID", newUser.ID,
					"error", err.Error())
				return apierrors.HandleDatabaseError(c, err)
			}

			// Commit the transaction
			if err := tx.Commit(ctx); err != nil {
				logger.Error("Failed to commit activation transaction",
					"username", pendingUser.Username.String,
					"userID", newUser.ID,
					"error", err.Error())
				return apierrors.HandleDatabaseError(c, err)
			}

			// Prepare success response
			resp = UserRegisterActivateResponse{
				Username: newUser.Username,
				Email:    newUser.Email.String,
			}

			logger.Info("User account activated successfully",
				"username", newUser.Username,
				"userID", newUser.ID,
				"email", newUser.Email.String)

			return nil
		})
		if err != nil {
			return err
		}

		return c.JSON(http.StatusOK, resp)
	})

	// If the error is ErrResponseSent, the response has already been sent
	// Return nil to prevent Echo from trying to send another response
	if errors.Is(err, apierrors.ErrResponseSent) {
		return nil
	}
	return err
}
