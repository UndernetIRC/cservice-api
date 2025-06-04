// SPDX-License-Identifier: MIT
// SPDX-FileCopyRightText: Copyright (c) 2023 UnderNET

package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/undernetirc/cservice-api/db/mocks"
	"github.com/undernetirc/cservice-api/internal/checks"
	"github.com/undernetirc/cservice-api/internal/config"
	apierrors "github.com/undernetirc/cservice-api/internal/errors"
	"github.com/undernetirc/cservice-api/internal/helper"
	"github.com/undernetirc/cservice-api/models"
)

func TestRoleController(t *testing.T) {
	config.DefaultConfig()

	jwtConfig := echojwt.Config{
		SigningMethod: config.ServiceJWTSigningMethod.GetString(),
		SigningKey:    helper.GetJWTPublicKey(),
		NewClaimsFunc: func(_ echo.Context) jwt.Claims {
			return new(helper.JwtClaims)
		},
	}

	claims := new(helper.JwtClaims)
	claims.UserID = 1
	claims.Username = "Admin"
	claims.Adm = 1000
	tokens, _ := helper.GenerateToken(claims, time.Now())

	t.Parallel()

	t.Run("AddUsersToRole", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		db.On("GetUsersByUsernames", mock.Anything, mock.Anything).
			Return([]models.GetUsersByUsernamesRow{
				{ID: 1, Username: "admin"},
				{ID: 2, Username: "test"},
			}, nil)
		db.On("AddUsersToRole", mock.Anything, mock.Anything).
			Return(int64(1), nil)

		checks.InitUser(context.Background(), db)
		c := NewAdminRoleController(db)

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.POST("/:id/users", c.AddUsersToRole, echojwt.WithConfig(jwtConfig))

		body := bytes.NewBufferString(`{"users": ["admin", "test"]}`)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest(http.MethodPost, "/1/users", body)
		r.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		r.Header.Set(echo.HeaderAuthorization, "Bearer "+tokens.AccessToken)

		e.ServeHTTP(w, r)
		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("AddUsersToRoleEmptyUserList", func(t *testing.T) {
		db := mocks.NewQuerier(t)

		checks.InitUser(context.Background(), db)
		c := NewAdminRoleController(db)

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.POST("/:id/users", c.AddUsersToRole, echojwt.WithConfig(jwtConfig))

		body := bytes.NewBufferString(``)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest(http.MethodPost, "/1/users", body)
		r.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		r.Header.Set(echo.HeaderAuthorization, "Bearer "+tokens.AccessToken)

		e.ServeHTTP(w, r)
		resp := w.Result()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

		errResp := new(apierrors.ErrorResponse)
		dec := json.NewDecoder(resp.Body)
		err := dec.Decode(&errResp)
		assert.NoError(t, err)
		assert.Contains(t, errResp.Error.Message, "users is a required field")
	})

	t.Run("RemoveUsersFromRole", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		db.On("GetUsersByUsernames", mock.Anything, mock.Anything).
			Return([]models.GetUsersByUsernamesRow{
				{ID: 1, Username: "admin"},
				{ID: 2, Username: "test"},
			}, nil)
		db.On("RemoveUsersFromRole", mock.Anything, mock.Anything, mock.Anything).
			Return(nil)

		checks.InitUser(context.Background(), db)
		c := NewAdminRoleController(db)

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.DELETE("/:id/users", c.RemoveUsersFromRole, echojwt.WithConfig(jwtConfig))

		body := bytes.NewBufferString(`{"users": ["admin", "test"]}`)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest(http.MethodDelete, "/1/users", body)
		r.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		r.Header.Set(echo.HeaderAuthorization, "Bearer "+tokens.AccessToken)

		e.ServeHTTP(w, r)
		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("RemoveUsersFromRole_EmptyUserList", func(t *testing.T) {
		db := mocks.NewQuerier(t)

		checks.InitUser(context.Background(), db)
		c := NewAdminRoleController(db)

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.DELETE("/:id/users", c.RemoveUsersFromRole, echojwt.WithConfig(jwtConfig))

		body := bytes.NewBufferString(``)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest(http.MethodDelete, "/1/users", body)
		r.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		r.Header.Set(echo.HeaderAuthorization, "Bearer "+tokens.AccessToken)

		e.ServeHTTP(w, r)
		res := w.Result()
		errResp := new(apierrors.ErrorResponse)
		dec := json.NewDecoder(res.Body)
		err := dec.Decode(&errResp)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, res.StatusCode)
		assert.Contains(t, errResp.Error.Message, "users is a required field")
	})

	t.Run("RemoveUsersFromRole_IncorrectRoleID", func(t *testing.T) {
		db := mocks.NewQuerier(t)

		checks.InitUser(context.Background(), db)
		c := NewAdminRoleController(db)

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.DELETE("/:id/users", c.RemoveUsersFromRole, echojwt.WithConfig(jwtConfig))

		body := bytes.NewBufferString(``)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest(http.MethodDelete, "/test/users", body)
		r.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		r.Header.Set(echo.HeaderAuthorization, "Bearer "+tokens.AccessToken)

		e.ServeHTTP(w, r)
		res := w.Result()
		assert.Equal(t, http.StatusBadRequest, res.StatusCode)
	})

	t.Run("CreateRole", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		db.On("CreateRole", mock.Anything, mock.Anything).
			Return(models.Role{ID: 1, Name: "test", Description: "test"}, nil)

		checks.InitUser(context.Background(), db)
		c := NewAdminRoleController(db)

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.POST("/", c.CreateRole, echojwt.WithConfig(jwtConfig))

		body := bytes.NewBufferString(`{"name": "test", "description": "test"}`)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest(http.MethodPost, "/", body)
		r.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		r.Header.Set(echo.HeaderAuthorization, "Bearer "+tokens.AccessToken)

		roleCeateResponse := &RoleCreateResponse{}
		e.ServeHTTP(w, r)
		resp := w.Result()
		dec := json.NewDecoder(resp.Body)
		err := dec.Decode(&roleCeateResponse)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusCreated, resp.StatusCode)
		assert.Equal(t, int32(1), roleCeateResponse.ID)
	})

	t.Run("DeleteRole", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		db.On("DeleteRole", mock.Anything, mock.Anything).
			Return(nil)

		checks.InitUser(context.Background(), db)
		c := NewAdminRoleController(db)

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.DELETE("/:id", c.DeleteRole, echojwt.WithConfig(jwtConfig))

		w := httptest.NewRecorder()
		r, _ := http.NewRequest(http.MethodDelete, "/1", nil)
		r.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		r.Header.Set(echo.HeaderAuthorization, "Bearer "+tokens.AccessToken)

		e.ServeHTTP(w, r)
		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("DeleteRole_RoleNotFound", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		db.On("DeleteRole", mock.Anything, mock.Anything).
			Return(pgx.ErrNoRows)

		checks.InitUser(context.Background(), db)
		c := NewAdminRoleController(db)

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.DELETE("/:id", c.DeleteRole, echojwt.WithConfig(jwtConfig))

		w := httptest.NewRecorder()
		r, _ := http.NewRequest(http.MethodDelete, "/1", nil)
		r.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		r.Header.Set(echo.HeaderAuthorization, "Bearer "+tokens.AccessToken)

		e.ServeHTTP(w, r)
		resp := w.Result()
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("DeleteRole_IncorrectID", func(t *testing.T) {
		db := mocks.NewQuerier(t)

		checks.InitUser(context.Background(), db)
		c := NewAdminRoleController(db)

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.DELETE("/:id", c.DeleteRole, echojwt.WithConfig(jwtConfig))

		w := httptest.NewRecorder()
		r, _ := http.NewRequest(http.MethodDelete, "/test", nil)
		r.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		r.Header.Set(echo.HeaderAuthorization, "Bearer "+tokens.AccessToken)

		e.ServeHTTP(w, r)
		resp := w.Result()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("CreateRole_AlreadyExists", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		db.On("CreateRole", mock.Anything, mock.Anything).
			Return(models.Role{}, &pgconn.PgError{Code: "23505"})

		checks.InitUser(context.Background(), db)
		c := NewAdminRoleController(db)

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.POST("/", c.CreateRole, echojwt.WithConfig(jwtConfig))

		body := bytes.NewBufferString(`{"name": "test", "description": "test"}`)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest(http.MethodPost, "/", body)
		r.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		r.Header.Set(echo.HeaderAuthorization, "Bearer "+tokens.AccessToken)

		e.ServeHTTP(w, r)
		resp := w.Result()
		assert.Equal(t, http.StatusConflict, resp.StatusCode)

		var errorResp apierrors.ErrorResponse
		dec := json.NewDecoder(resp.Body)
		err := dec.Decode(&errorResp)
		assert.NoError(t, err)
		assert.Contains(t, errorResp.Error.Message, "already exists")
	})

	t.Run("UpdateRole", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		db.On("GetRoleByID", mock.Anything, int32(1)).
			Return(models.Role{}, nil)
		db.On("UpdateRole", mock.Anything, mock.Anything).
			Return(nil)

		checks.InitUser(context.Background(), db)
		c := NewAdminRoleController(db)

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.PUT("/:id", c.UpdateRole, echojwt.WithConfig(jwtConfig))

		body := bytes.NewBufferString(`{"name": "test", "description": "test"}`)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest(http.MethodPut, "/1", body)
		r.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		r.Header.Set(echo.HeaderAuthorization, "Bearer "+tokens.AccessToken)

		response := &roleUpdateResponse{}
		e.ServeHTTP(w, r)
		resp := w.Result()
		dec := json.NewDecoder(resp.Body)
		err := dec.Decode(&response)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, int32(1), response.ID)
	})

	t.Run("UpdateRole_NotFound", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		db.On("GetRoleByID", mock.Anything, int32(1)).
			Return(models.Role{}, pgx.ErrNoRows)

		checks.InitUser(context.Background(), db)
		c := NewAdminRoleController(db)

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.PUT("/:id", c.UpdateRole, echojwt.WithConfig(jwtConfig))

		body := bytes.NewBufferString(`{"name": "test", "description": "test"}`)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest(http.MethodPut, "/1", body)
		r.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		r.Header.Set(echo.HeaderAuthorization, "Bearer "+tokens.AccessToken)

		e.ServeHTTP(w, r)
		resp := w.Result()
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("UpdateRole_FailedValidation", func(t *testing.T) {
		db := mocks.NewQuerier(t)

		checks.InitUser(context.Background(), db)
		c := NewAdminRoleController(db)

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.PUT("/:id", c.UpdateRole, echojwt.WithConfig(jwtConfig))

		body := bytes.NewBufferString(`{"name": "", "description": "test"}`)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest(http.MethodPut, "/1", body)
		r.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		r.Header.Set(echo.HeaderAuthorization, "Bearer "+tokens.AccessToken)

		e.ServeHTTP(w, r)
		resp := w.Result()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("GetRoles", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		db.On("ListRoles", mock.Anything).
			Return([]models.Role{
				{ID: 1, Name: "test", Description: "test"},
				{ID: 2, Name: "test2", Description: "test2"},
			}, nil)

		checks.InitUser(context.Background(), db)
		c := NewAdminRoleController(db)

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.GET("/", c.GetRoles, echojwt.WithConfig(jwtConfig))

		w := httptest.NewRecorder()
		r, _ := http.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		r.Header.Set(echo.HeaderAuthorization, "Bearer "+tokens.AccessToken)

		response := &RoleListResponse{}
		e.ServeHTTP(w, r)
		res := w.Result()
		dec := json.NewDecoder(res.Body)
		err := dec.Decode(&response)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode)
		assert.Equal(t, 2, len(response.Roles))
	})
}
