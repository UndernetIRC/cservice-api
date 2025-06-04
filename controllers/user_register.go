package controllers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/labstack/echo/v4"

	"github.com/undernetirc/cservice-api/db"
	"github.com/undernetirc/cservice-api/internal/checks"
	"github.com/undernetirc/cservice-api/internal/config"
	apierrors "github.com/undernetirc/cservice-api/internal/errors"
	"github.com/undernetirc/cservice-api/internal/helper"
	"github.com/undernetirc/cservice-api/internal/mail"
	"github.com/undernetirc/cservice-api/models"
)

// PoolInterface defines the interface for database pool operations
type PoolInterface interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}

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

	// Check if the username or email is already taken
	err := checks.User.IsRegistered(req.Username, req.Email)
	if err != nil && !errors.Is(err, checks.ErrUsernameExists) &&
		!errors.Is(err, checks.ErrEmailExists) {
		logger.Error("Error during user registration check",
			"username", req.Username,
			"email", req.Email,
			"error", err.Error())
		return apierrors.HandleInternalError(c, err, "Failed to check user registration status")
	} else if err != nil {
		logger.Warn("Registration attempt with existing credentials",
			"username", req.Username,
			"email", req.Email,
			"error", err.Error())
		return apierrors.HandleConflictError(c, err.Error())
	}

	// Create the pending user
	cookie := helper.GenerateSecureToken(32)
	user := new(models.CreatePendingUserParams)
	user.Username = db.NewString(req.Username)
	user.Email = db.NewString(req.Email)
	user.Cookie = db.NewString(cookie)
	user.Language = db.NewInt4(1)
	user.PosterIp = db.NewString(c.RealIP())
	expirationHours := config.ServicePendingUserExpirationHours.GetInt64()
	expirationTime := time.Now().Add(time.Duration(expirationHours) * time.Hour)
	user.Expire = db.NewInt4(expirationTime.Unix())

	if err := user.Password.Set(req.Password); err != nil {
		logger.Error("Failed to hash password during registration",
			"username", req.Username,
			"error", err.Error())
		return apierrors.HandleInternalError(c, err, "Failed to process password")
	}

	if _, err = ctr.s.CreatePendingUser(c.Request().Context(), *user); err != nil {
		logger.Error("Failed to create pending user",
			"username", req.Username,
			"email", req.Email,
			"error", err.Error())
		return apierrors.HandleDatabaseError(c, err)
	}

	// Only send email if mail service is enabled
	if config.ServiceMailEnabled.GetBool() {
		// Generate the activation URL with the cookie token
		baseURL := config.ServiceBaseURL.GetString()
		activationURL := fmt.Sprintf("%s/activate?token=%s", baseURL, cookie)

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
		} else {
			logger.Info("Registration email sent successfully",
				"username", req.Username,
				"email", req.Email)
		}
	} else {
		logger.Info("Mail service disabled, skipping registration email")
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

	ctx := c.Request().Context()
	req := new(UserRegisterActivateRequest)

	if err := c.Bind(req); err != nil {
		return apierrors.HandleBadRequestError(c, "Invalid request format")
	}

	if err := c.Validate(req); err != nil {
		return apierrors.HandleValidationError(c, err)
	}

	pendingUser, err := ctr.s.GetPendingUserByCookie(ctx, db.NewString(req.Token))
	if err != nil {
		logger.Warn("Account activation attempt with invalid token",
			"token", req.Token,
			"error", err.Error())
		return apierrors.HandleNotFoundError(c, "User")
	}

	// Check if the pending user record has expired
	currentTime := time.Now().Unix()
	if currentTime > int64(pendingUser.Expire.Int32) {
		err := ctr.s.DeletePendingUserByCookie(ctx, pendingUser.Cookie)
		if err != nil {
			logger.Error("Failed to delete expired pending user",
				"username", pendingUser.Username.String,
				"error", err.Error())
		}
		logger.Warn("Account activation attempted with expired token",
			"username", pendingUser.Username.String,
			"token", req.Token)
		return apierrors.HandleUnauthorizedError(c, "Activation token has expired")
	}

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

	// Return success response
	resp := UserRegisterActivateResponse{
		Username: newUser.Username,
		Email:    newUser.Email.String,
	}

	logger.Info("User account activated successfully",
		"username", newUser.Username,
		"userID", newUser.ID,
		"email", newUser.Email.String)

	return c.JSON(http.StatusOK, resp)
}
