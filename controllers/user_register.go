package controllers

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"

	"github.com/undernetirc/cservice-api/db"
	"github.com/undernetirc/cservice-api/internal/checks"
	"github.com/undernetirc/cservice-api/internal/config"
	"github.com/undernetirc/cservice-api/internal/helper"
	"github.com/undernetirc/cservice-api/internal/mail"
	"github.com/undernetirc/cservice-api/models"
)

// UserRegisterController is the controller for the authentication routes
type UserRegisterController struct {
	s    models.ServiceInterface
	pool *pgxpool.Pool
}

// NewUserRegisterController returns a new UserRegisterController
func NewUserRegisterController(s models.ServiceInterface, pool *pgxpool.Pool) *UserRegisterController {
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
// @Failure 400 {object} customError "Bad request"
// @Failure 500 {object} customError "Internal server error"
// @Router /register [post]
func (ctr *UserRegisterController) UserRegister(c echo.Context) error {
	req := new(UserRegisterRequest)
	// if err := helper.BindAndValidateRequest(c, req); err != nil {
	// 	return err // Error response already sent by helper
	// }

	if err := c.Bind(req); err != nil {
		return c.JSON(http.StatusBadRequest, err.Error())
	}

	if err := c.Validate(req); err != nil {
		c.Logger().Error(err)
		return c.JSON(http.StatusBadRequest, customError{
			Code:    http.StatusBadRequest,
			Message: err.Error(),
		})
	}

	// Check if the username or email is already taken
	err := checks.User.IsRegistered(req.Username, req.Email)
	if err != nil && !errors.Is(err, checks.ErrUsernameExists) &&
		!errors.Is(err, checks.ErrEmailExists) {
		c.Logger().Error(err)
		return c.JSON(http.StatusInternalServerError, customError{
			Code:    http.StatusInternalServerError,
			Message: "Internal server error",
		})
	} else if err != nil {
		return c.JSON(http.StatusConflict, customError{
			Code:    http.StatusConflict,
			Message: err.Error(),
		})
	}

	// Create the pending user
	cookie := helper.GenerateSecureToken(32)
	user := new(models.CreatePendingUserParams)
	user.Username = db.NewString(req.Username)
	user.Email = db.NewString(req.Email)
	user.Cookie = db.NewString(cookie)
	user.Language = db.NewInt4(1)
	user.PosterIp = db.NewString(c.RealIP())
	user.Expire = db.NewInt4(
		time.Now().Add(time.Hour * time.Duration(config.ServicePendingUserExpirationHours.GetUint())).Unix(),
	)

	if err := user.Password.Set(req.Password); err != nil {
		c.Logger().Error(err)
		return c.JSON(http.StatusInternalServerError, customError{
			Code:    http.StatusInternalServerError,
			Message: err.Error(),
		})
	}

	if _, err = ctr.s.CreatePendingUser(c.Request().Context(), *user); err != nil {
		c.Logger().Error(err)
		return c.JSON(http.StatusInternalServerError, customError{
			Code:    http.StatusInternalServerError,
			Message: err.Error(),
		})
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
			c.Logger().Error(err)
		}
	} else {
		c.Logger().Info("Mail service disabled, skipping registration email")
	}

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
// @Failure 400 {object} customError "Bad request"
// @Failure 401 {object} customError "Unauthorized"
// @Failure 404 {object} customError "Not found"
// @Failure 500 {object} customError "Internal server error"
// @Router /activate [post]
func (ctr *UserRegisterController) UserActivateAccount(c echo.Context) error {
	ctx := c.Request().Context()
	req := new(UserRegisterActivateRequest)
	if err := helper.BindAndValidateRequest(c, req); err != nil {
		return err // Error response already sent by helper
	}

	pendingUser, err := ctr.s.GetPendingUserByCookie(ctx, db.NewString(req.Token))
	if err != nil {
		return c.JSON(http.StatusNotFound, customError{
			Code:    http.StatusNotFound,
			Message: "User not found",
		})
	}

	// Check if the pending user record has expired
	if int32(time.Now().Unix()) > pendingUser.Expire.Int32 {
		err := ctr.s.DeletePendingUserByCookie(ctx, pendingUser.Cookie)
		if err != nil {
			c.Logger().Errorf("Failed to delete expired pending user %d: %v", pendingUser.Username, err)
			return c.JSON(http.StatusUnauthorized, customError{
				Code:    http.StatusUnauthorized,
				Message: "Activation token has expired",
			})
		}
	}

	// Start transaction
	tx, err := ctr.pool.Begin(ctx)
	if err != nil {
		c.Logger().Error(err)
		return c.JSON(http.StatusInternalServerError, customError{
			Code:    http.StatusInternalServerError,
			Message: "Failed to start database transaction",
		})
	}
	defer tx.Rollback(ctx) // Rollback if anything fails

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
		// PosterIp: pendingUser.PosterIp, // Assuming PosterIp is not needed or handled differently in the main user table
		// Add any other necessary fields from pendingUser or defaults
	}
	newUser, err := qtx.CreateUser(ctx, createUserParams)
	if err != nil {
		c.Logger().Errorf("Failed to create user from pending user %d: %v", pendingUser.Username, err)
		return c.JSON(http.StatusInternalServerError, customError{
			Code:    http.StatusInternalServerError,
			Message: "Failed to activate account",
		})
	}

	// Delete the pending user record
	err = qtx.DeletePendingUserByCookie(ctx, pendingUser.Cookie)
	if err != nil {
		c.Logger().Errorf("Failed to delete pending user %d after activation: %v", pendingUser.Username, err)
		// Don't necessarily fail the whole activation if pending user deletion fails,
		// but log it seriously. Consider adding cleanup mechanisms.
		// For now, we'll treat it as a failure to ensure consistency.
		return c.JSON(http.StatusInternalServerError, customError{
			Code:    http.StatusInternalServerError,
			Message: "Failed to finalize account activation",
		})
	}

	// Commit the transaction
	if err := tx.Commit(ctx); err != nil {
		c.Logger().Error(err)
		return c.JSON(http.StatusInternalServerError, customError{
			Code:    http.StatusInternalServerError,
			Message: "Failed to commit activation transaction",
		})
	}

	// Return success response
	resp := UserRegisterActivateResponse{
		Username: newUser.Username,
		Email:    newUser.Email.String,
	}

	return c.JSON(http.StatusOK, resp)
}
