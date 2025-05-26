package controllers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/undernetirc/cservice-api/db/mocks"
	"github.com/undernetirc/cservice-api/internal/checks"
	"github.com/undernetirc/cservice-api/internal/helper"
)

func TestUserRegisterController_Register(t *testing.T) {
	username := "Admin"
	email := "test@example.com"
	userList := []string{}
	emailList := []pgtype.Text{}
	registration := UserRegisterRequest{
		Username:        username,
		Email:           email,
		Password:        "testPassW0rd",
		ConfirmPassword: "testPassW0rd",
		AUP:             true,
		COPPA:           true,
	}
	registrationJSON, _ := json.Marshal(registration)

	testCases := []struct {
		username        string
		email           string
		password        string
		confirmPassword string
		aup             bool
		coppa           bool
		error           []string
	}{
		// Should fail validation missing fields/false values
		{
			username:        "invalid1",
			password:        "testPassW0rd",
			confirmPassword: "testPassW0rd",
			aup:             true,
			coppa:           true,
			error:           []string{"email is a required field"},
		},
		{
			username:        "invalid2",
			email:           email,
			password:        "testPassW0rd",
			confirmPassword: "testPassW0rd",
			aup:             false,
			coppa:           true,
			error:           []string{"aup is a required field"},
		},
		{
			username:        "invalid3",
			email:           email,
			password:        "testPassW0rd",
			confirmPassword: "testPassW0rd",
			aup:             true,
			coppa:           false,
			error:           []string{"coppa is a required field"},
		},
		{
			username:        "invalid4",
			email:           email,
			password:        "testPassW0rd",
			confirmPassword: "testPassW0rd",
			aup:             false,
			coppa:           false,
			error:           []string{"aup is a required field", "coppa is a required field"},
		},

		// Should fail validation too short or invalid values
		{
			username:        "i",
			email:           email,
			password:        "testPassW0rd",
			confirmPassword: "testPassW0rd",
			aup:             true,
			coppa:           true,
			error:           []string{"username must be at least"},
		},
		{
			username:        "thisisaverylongusername",
			email:           email,
			password:        "testPassW0rd",
			confirmPassword: "testPassW0rd",
			aup:             true,
			coppa:           true,
			error:           []string{"username must be a maximum"},
		},
		{
			username:        "invalid7",
			email:           email,
			password:        "short",
			confirmPassword: "short",
			aup:             true,
			coppa:           true,
			error:           []string{"password must be at least"},
		},
		{
			username:        "j",
			email:           email,
			password:        "short",
			confirmPassword: "short",
			aup:             true,
			coppa:           true,
			error:           []string{"username must be at least", "password must be at least"},
		},
		{
			username:        "invalid8",
			email:           "invalid",
			password:        "testPassW0rd",
			confirmPassword: "testPassW0re",
			aup:             true,
			coppa:           true,
			error:           []string{"email must be a valid email address"},
		},
		{
			username:        "invalid9",
			email:           email,
			password:        strings.Repeat("a", 80),
			confirmPassword: strings.Repeat("a", 80),
			aup:             true,
			coppa:           true,
			error:           []string{"password must be a maximum of"},
		},
		{
			username:        "passwordneq",
			email:           email,
			password:        "1234567890",
			confirmPassword: "0987654321",
			aup:             true,
			coppa:           true,
			error:           []string{"confirm_password must be equal to Password"},
		},

		// Valid test
		{
			username:        "valid",
			email:           email,
			password:        "testPassW0rd",
			confirmPassword: "testPassW0rd",
			aup:             true,
			coppa:           true,
			error:           []string{},
		},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("testing register input validation %s", tc.username), func(t *testing.T) {
			db := mocks.NewServiceInterface(t)
			if len(tc.error) == 0 {
				db.On("CheckUsernameExists", mock.Anything, tc.username).
					Return(userList, nil).Once()
				db.On("CheckEmailExists", mock.Anything, tc.email).
					Return(emailList, nil).Once()
				db.On("CreatePendingUser", mock.Anything, mock.Anything).
					Return(pgtype.Text{}, nil).Once()
			}

			checks.InitUser(context.Background(), db)
			controller := NewUserRegisterController(db, nil)

			e := echo.New()
			e.Validator = helper.NewValidator()
			e.POST("/register", controller.Register)

			j, _ := json.Marshal(UserRegisterRequest{
				Username:        tc.username,
				Email:           tc.email,
				Password:        tc.password,
				ConfirmPassword: tc.confirmPassword,
				AUP:             tc.aup,
				COPPA:           tc.coppa,
			})

			body := bytes.NewBufferString(string(j))
			w := httptest.NewRecorder()
			r, _ := http.NewRequest(http.MethodPost, "/register", body)
			r.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

			e.ServeHTTP(w, r)
			resp := w.Result()
			if resp.StatusCode != http.StatusCreated {
				errorResponse := new(customError)
				err := json.NewDecoder(resp.Body).Decode(errorResponse)
				assert.Nil(t, err)
				assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
				for _, e := range tc.error {
					assert.Contains(t, errorResponse.Message, e)
				}
			}
		})
	}

	t.Run("fail register because username exists", func(t *testing.T) {
		db := mocks.NewServiceInterface(t)
		db.On("CheckUsernameExists", mock.Anything, username).
			Return(userList, checks.ErrUsernameExists).Once()
		db.On("CheckEmailExists", mock.Anything, email).
			Return(emailList, nil).Once()

		checks.InitUser(context.Background(), db)
		controller := NewUserRegisterController(db, nil)

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.POST("/register", controller.Register)

		body := bytes.NewBufferString(string(registrationJSON))
		w := httptest.NewRecorder()
		r, _ := http.NewRequest(http.MethodPost, "/register", body)
		r.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		e.ServeHTTP(w, r)
		resp := w.Result()

		errorResponse := new(customError)
		err := json.NewDecoder(resp.Body).Decode(&errorResponse)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusConflict, resp.StatusCode)
		assert.Equal(t, checks.ErrUsernameExists.Error(), errorResponse.Message)
	})

	t.Run("fail register because username exists", func(t *testing.T) {
		db := mocks.NewServiceInterface(t)
		db.On("CheckUsernameExists", mock.Anything, username).
			Return(userList, checks.ErrUsernameExists).Once()
		db.On("CheckEmailExists", mock.Anything, email).
			Return(emailList, checks.ErrEmailExists).Once()

		checks.InitUser(context.Background(), db)
		controller := NewUserRegisterController(db, nil)

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.POST("/register", controller.Register)

		body := bytes.NewBufferString(string(registrationJSON))
		w := httptest.NewRecorder()
		r, _ := http.NewRequest(http.MethodPost, "/register", body)
		r.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		e.ServeHTTP(w, r)
		resp := w.Result()

		errorResponse := new(customError)
		err := json.NewDecoder(resp.Body).Decode(&errorResponse)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusConflict, resp.StatusCode)
		assert.Contains(t, errorResponse.Message, checks.ErrUsernameExists.Error())
		assert.Contains(t, errorResponse.Message, checks.ErrEmailExists.Error())
	})
}
