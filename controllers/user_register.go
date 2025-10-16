package controllers

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"

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

	var cookie string

	err := tracing.NewOperation("user_registration").
		WithContext(c.Request().Context()).
		WithAttributes(map[string]interface{}{
			"username":   req.Username,
			"email":      req.Email,
			"ip_address": c.RealIP(),
		}).
		AddStage("validate_credentials", func(tc *tracing.TracedContext) error {
			tracing.AddHTTPRequestAttrs(tc, c)
			tracing.AddEmailAttrs(tc, req.Email)
			tracing.AddUsernameAttrs(tc, req.Username)

			err := checks.User.IsRegistered(req.Username, req.Email)
			if err != nil && !errors.Is(err, checks.ErrUsernameExists) &&
				!errors.Is(err, checks.ErrEmailExists) {
				logger.Error("Error during user registration check",
					"username", req.Username,
					"email", req.Email,
					"error", err.Error())
				tc.AddAttr("validation.error_type", "database_error")
				tc.RecordError(err)
				return apierrors.HandleInternalError(c, err, "Failed to check user registration status")
			} else if err != nil {
				logger.Warn("Registration attempt with existing credentials",
					"username", req.Username,
					"email", req.Email,
					"error", err.Error())
				if errors.Is(err, checks.ErrUsernameExists) {
					tc.AddAttr("validation.conflict_type", "username_exists")
				} else if errors.Is(err, checks.ErrEmailExists) {
					tc.AddAttr("validation.conflict_type", "email_exists")
				}
				return apierrors.HandleConflictError(c, err.Error())
			}
			tc.AddAttr("validation.credentials_available", true)
			tc.MarkSuccess()
			return nil
		}).
		AddStage("create_pending_user", func(tc *tracing.TracedContext) error {
			expirationHours := config.ServicePendingUserExpirationHours.GetInt64()
			expirationTime := time.Now().Add(time.Duration(expirationHours) * time.Hour)

			tc.AddAttrs(map[string]interface{}{
				"pending_user.expiration_hours": expirationHours,
				"pending_user.expiration_time":  expirationTime.Format(time.RFC3339),
				"pending_user.language_id":      1,
				"pending_user.password_length":  len(req.Password),
			})

			cookie = helper.GenerateSecureToken(32)
			user := &models.CreatePendingUserParams{
				Username: db.NewString(req.Username),
				Email:    db.NewString(req.Email),
				Cookie:   db.NewString(cookie),
				Language: db.NewInt4(1),
				PosterIp: db.NewString(c.RealIP()),
				Expire:   db.NewInt4(expirationTime.Unix()),
			}

			tracing.AddTokenAttrs(tc, cookie, "activation")

			if err := user.Password.Set(req.Password); err != nil {
				logger.Error("Failed to hash password during registration",
					"username", req.Username,
					"error", err.Error())
				tc.RecordError(err)
				return apierrors.HandleInternalError(c, err, "Failed to process password")
			}

			tc.AddAttr("pending_user.password_hashed", true)

			if _, err := ctr.s.CreatePendingUser(tc.Context, *user); err != nil {
				logger.Error("Failed to create pending user",
					"username", req.Username,
					"email", req.Email,
					"error", err.Error())
				tc.RecordError(err)
				return apierrors.HandleDatabaseError(c, err)
			}

			tracing.AddDatabaseOperationAttrs(tc, "INSERT", "pendingusers", 1)
			tc.MarkSuccess()
			return nil
		}).
		AddOptionalStage("send_activation_email", func(tc *tracing.TracedContext) error {
			mailEnabled := config.ServiceMailEnabled.GetBool()
			baseURL := config.ServiceBaseURL.GetString()

			tc.AddAttrs(map[string]interface{}{
				"email.service_enabled": mailEnabled,
				"email.base_url":        baseURL,
			})

			if !mailEnabled {
				logger.Info("Mail service disabled, skipping registration email")
				tc.AddAttr("email.skip_reason", "service_disabled")
				return nil
			}

			activationURL := fmt.Sprintf("%s/activate?token=%s", baseURL, cookie)
			templateData := map[string]any{
				"Username":      req.Username,
				"ActivationURL": activationURL,
				"Year":          time.Now().Year(),
			}

			tracing.AddMailOperationAttrs(tc, req.Email, "Activate your UnderNET CService account", "registration")

			m := mail.NewMail(req.Email, "Activate your UnderNET CService account", "registration", templateData)
			if err := m.Send(); err != nil {
				logger.Error("Failed to send registration email",
					"username", req.Username,
					"email", req.Email,
					"error", err.Error())
				tc.RecordError(err)
				return err
			}

			logger.Info("Registration email sent successfully",
				"username", req.Username,
				"email", req.Email)
			tc.AddAttr("email.sent", true)
			tc.MarkSuccess()
			return nil
		}).
		Execute()

	if err != nil {
		if errors.Is(err, apierrors.ErrResponseSent) {
			return nil
		}
		return err
	}

	logger.Info("User registration initiated successfully",
		"username", req.Username,
		"email", req.Email,
		"ip", c.RealIP())

	return c.NoContent(http.StatusCreated)
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

	var pendingUser models.Pendinguser
	var resp UserRegisterActivateResponse

	err := tracing.NewOperation("user_activation").
		WithContext(c.Request().Context()).
		WithAttributes(map[string]interface{}{
			"ip_address": c.RealIP(),
		}).
		AddStage("validate_token", func(tc *tracing.TracedContext) error {
			tracing.AddHTTPRequestAttrs(tc, c)
			tracing.AddTokenAttrs(tc, req.Token, "activation")

			var err error
			pendingUser, err = ctr.s.GetPendingUserByCookie(tc.Context, db.NewString(req.Token))
			if err != nil {
				logger.Warn("Account activation attempt with invalid token",
					"token", req.Token,
					"error", err.Error())
				tc.AddAttr("activation.token_found", false)
				tc.RecordError(err)
				return apierrors.HandleNotFoundError(c, "User")
			}

			tracing.AddEmailAttrs(tc, pendingUser.Email.String)
			tracing.AddUsernameAttrs(tc, pendingUser.Username.String)

			tc.AddAttrs(map[string]interface{}{
				"activation.token_found":          true,
				"activation.username":             pendingUser.Username.String,
				"activation.expiration_timestamp": int64(pendingUser.Expire.Int32),
			})

			currentTime := time.Now().Unix()
			timeUntilExpiry := int64(pendingUser.Expire.Int32) - currentTime

			tc.AddAttrs(map[string]interface{}{
				"activation.current_timestamp":         currentTime,
				"activation.time_until_expiry_seconds": timeUntilExpiry,
				"activation.is_expired":                timeUntilExpiry <= 0,
			})

			if currentTime > int64(pendingUser.Expire.Int32) {
				if err := ctr.s.DeletePendingUserByCookie(tc.Context, pendingUser.Cookie); err != nil {
					logger.Error("Failed to delete expired pending user",
						"username", pendingUser.Username.String,
						"error", err.Error())
					tc.AddAttr("activation.cleanup_error", err.Error())
				} else {
					tc.AddAttr("activation.expired_record_cleaned", true)
				}
				logger.Warn("Account activation attempted with expired token",
					"username", pendingUser.Username.String,
					"token", req.Token)
				return apierrors.HandleUnauthorizedError(c, "Activation token has expired")
			}

			tc.AddAttr("activation.token_valid", true)
			tc.MarkSuccess()
			return nil
		}).
		AddStage("activate_user", func(tc *tracing.TracedContext) error {
			tx, err := ctr.pool.Begin(tc.Context)
			if err != nil {
				logger.Error("Failed to start database transaction for activation",
					"username", pendingUser.Username.String,
					"error", err.Error())
				tc.RecordError(err)
				return apierrors.HandleDatabaseError(c, err)
			}
			defer func() {
				if rollbackErr := tx.Rollback(tc.Context); rollbackErr != nil {
					logger.Error("Failed to rollback transaction",
						"error", rollbackErr.Error())
				}
			}()

			qtx := ctr.s.WithTx(tx)

			createUserParams := models.CreateUserParams{
				Username:   pendingUser.Username.String,
				Password:   pendingUser.Password,
				Email:      pendingUser.Email,
				LanguageID: pendingUser.Language,
				SignupTs:   db.NewInt4(time.Now().UTC().Unix()),
				SignupIp:   db.NewString(c.RealIP()),
				Maxlogins:  db.NewInt4(1),
			}

			newUser, err := qtx.CreateUser(tc.Context, createUserParams)
			if err != nil {
				logger.Error("Failed to create user from pending user",
					"username", pendingUser.Username.String,
					"error", err.Error())
				tc.RecordError(err)
				return apierrors.HandleDatabaseError(c, err)
			}

			tracing.AddDatabaseOperationAttrs(tc, "INSERT", "users", 1)
			tc.AddAttr("user.id", newUser.ID)

			err = qtx.DeletePendingUserByCookie(tc.Context, pendingUser.Cookie)
			if err != nil {
				logger.Error("Failed to delete pending user after activation",
					"username", pendingUser.Username.String,
					"userID", newUser.ID,
					"error", err.Error())
				tc.RecordError(err)
				return apierrors.HandleDatabaseError(c, err)
			}

			tracing.AddDatabaseOperationAttrs(tc, "DELETE", "pendingusers", 1)

			if err := tx.Commit(tc.Context); err != nil {
				logger.Error("Failed to commit activation transaction",
					"username", pendingUser.Username.String,
					"userID", newUser.ID,
					"error", err.Error())
				tc.RecordError(err)
				return apierrors.HandleDatabaseError(c, err)
			}

			resp = UserRegisterActivateResponse{
				Username: newUser.Username,
				Email:    newUser.Email.String,
			}

			logger.Info("User account activated successfully",
				"username", newUser.Username,
				"userID", newUser.ID,
				"email", newUser.Email.String)

			tc.MarkSuccess()
			return nil
		}).
		Execute()

	if err != nil {
		if errors.Is(err, apierrors.ErrResponseSent) {
			return nil
		}
		return err
	}

	return c.JSON(http.StatusOK, resp)
}
