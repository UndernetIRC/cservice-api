// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023-2024 UnderNET

package controllers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-redis/redismock/v9"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgtype"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/undernetirc/cservice-api/db/mocks"
	"github.com/undernetirc/cservice-api/db/types/flags"
	"github.com/undernetirc/cservice-api/internal/auth/oath/totp"
	"github.com/undernetirc/cservice-api/internal/checks"
	"github.com/undernetirc/cservice-api/internal/config"
	"github.com/undernetirc/cservice-api/internal/helper"
	"github.com/undernetirc/cservice-api/models"
)

func TestAuthenticationController_Register(t *testing.T) {
	username := "Admin"
	email := "test@example.com"
	userList := []string{}
	emailList := []pgtype.Text{}
	registration := RegisterRequest{
		Username: username,
		Email:    email,
		Password: "testPassW0rd",
		EULA:     true,
		COPPA:    true,
	}
	registrationJSON, _ := json.Marshal(registration)

	testCases := []struct {
		username string
		email    string
		password string
		eula     bool
		coppa    bool
		error    []string
	}{
		// Should fail validation missing fields/false values
		{
			username: "invalid1",
			password: "testPassW0rd",
			eula:     true,
			coppa:    true,
			error:    []string{"email is a required field"},
		},
		{
			username: "invalid2",
			email:    email,
			password: "testPassW0rd",
			eula:     false,
			coppa:    true,
			error:    []string{"eula is a required field"},
		},
		{
			username: "invalid3",
			email:    email,
			password: "testPassW0rd",
			eula:     true,
			coppa:    false,
			error:    []string{"coppa is a required field"},
		},
		{
			username: "invalid4",
			email:    email,
			password: "testPassW0rd",
			eula:     false,
			coppa:    false,
			error:    []string{"eula is a required field", "coppa is a required field"},
		},

		// Should fail validation too short or invalid values
		{
			username: "i",
			email:    email,
			password: "testPassW0rd",
			eula:     true,
			coppa:    true,
			error:    []string{"username must be at least"},
		},
		{
			username: "thisisaverylongusername",
			email:    email,
			password: "testPassW0rd",
			eula:     true,
			coppa:    true,
			error:    []string{"username must be a maximum"},
		},
		{
			username: "invalid7",
			email:    email,
			password: "short",
			eula:     true,
			coppa:    true,
			error:    []string{"password must be at least"},
		},
		{
			username: "j",
			email:    email,
			password: "short",
			eula:     true,
			coppa:    true,
			error:    []string{"username must be at least", "password must be at least"},
		},
		{
			username: "invalid8",
			email:    "invalid",
			password: "testPassW0rd",
			eula:     true,
			coppa:    true,
			error:    []string{"email must be a valid email address"},
		},
		{
			username: "invalid9",
			email:    email,
			password: strings.Repeat("a", 80),
			eula:     true,
			coppa:    true,
			error:    []string{"password must be a maximum of"},
		},

		// Valid test
		{username: "valid", email: email, password: "testPassW0rd", eula: true, coppa: true, error: []string{}},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("testing register input validation %s", tc.username), func(t *testing.T) {
			db := mocks.NewQuerier(t)
			if len(tc.error) == 0 {
				db.On("CheckUsernameExists", mock.Anything, tc.username).
					Return(userList, nil).Once()
				db.On("CheckEmailExists", mock.Anything, tc.email).
					Return(emailList, nil).Once()
				db.On("CreatePendingUser", mock.Anything, mock.Anything).
					Return(pgtype.Text{}, nil).Once()
			}

			rdb, _ := redismock.NewClientMock()
			checks.InitUser(context.Background(), db)
			authController := NewAuthenticationController(db, rdb, nil)

			e := echo.New()
			e.Validator = helper.NewValidator()
			e.POST("/register", authController.Register)

			j, _ := json.Marshal(RegisterRequest{
				Username: tc.username,
				Email:    tc.email,
				Password: tc.password,
				EULA:     tc.eula,
				COPPA:    tc.coppa,
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
		db := mocks.NewQuerier(t)
		db.On("CheckUsernameExists", mock.Anything, username).
			Return(userList, checks.ErrUsernameExists).Once()
		db.On("CheckEmailExists", mock.Anything, email).
			Return(emailList, nil).Once()
		rdb, _ := redismock.NewClientMock()

		checks.InitUser(context.Background(), db)
		authController := NewAuthenticationController(db, rdb, nil)

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.POST("/register", authController.Register)

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
		db := mocks.NewQuerier(t)
		db.On("CheckUsernameExists", mock.Anything, username).
			Return(userList, checks.ErrUsernameExists).Once()
		db.On("CheckEmailExists", mock.Anything, email).
			Return(emailList, checks.ErrEmailExists).Once()
		rdb, _ := redismock.NewClientMock()

		checks.InitUser(context.Background(), db)
		authController := NewAuthenticationController(db, rdb, nil)

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.POST("/register", authController.Register)

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

func TestAuthenticationController_Login(t *testing.T) {
	seed := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	config.DefaultConfig()
	n := time.Now()
	timeMock := func() time.Time {
		return n
	}
	rt := time.Unix(timeMock().Add(time.Hour*24*7).Unix(), 0)

	t.Run("valid login without OTP", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		db.On("GetUserByUsername", mock.Anything, "Admin").
			Return(models.User{
				ID:       1,
				Username: "Admin",
				Password: "xEDi1V791f7bddc526de7e3b0602d0b2993ce21d",
				TotpKey:  pgtype.Text{String: "", Valid: true},
			}, nil).Once()
		db.On("GetUserByID", mock.Anything, int32(1)).
			Return(models.GetUserByIDRow{
				ID:       1,
				Username: "Admin",
				Flags:    0,
				TotpKey:  pgtype.Text{String: "", Valid: true},
			}, nil).Once()
		db.On("GetAdminLevel", mock.Anything, int32(1)).
			Return(models.GetAdminLevelRow{}, nil).Once()
		db.On("ListUserRoles", mock.Anything, int32(1)).
			Return([]models.Role{}, nil).Once()

		rdb, rmock := redismock.NewClientMock()
		rmock.Regexp().ExpectSet("user:1:rt:", `.*`, rt.Sub(timeMock())).SetVal("1")

		checks.InitUser(context.Background(), db)
		authController := NewAuthenticationController(db, rdb, timeMock)

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.POST("/login", authController.Login)

		body := bytes.NewBufferString(`{"username": "Admin", "password": "temPass2020@"}`)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("POST", "/login", body)
		r.Header.Set("Content-Type", "application/json")

		e.ServeHTTP(w, r)
		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		err := rmock.ExpectationsWereMet()
		assert.Equal(t, nil, err)
		rmock.ClearExpect()

		loginResponse := new(LoginResponse)
		dec := json.NewDecoder(resp.Body)
		if err := dec.Decode(&loginResponse); err != nil {
			t.Error("error decoding", err)
		}

		token, err := jwt.ParseWithClaims(
			loginResponse.AccessToken,
			&helper.JwtClaims{},
			func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, errors.New("unexpected signing method")
				}
				return []byte(config.ServiceJWTSigningSecret.GetString()), nil
			},
		)
		if err != nil {
			t.Error("error parsing token", err)
		}

		claims := token.Claims.(*helper.JwtClaims)

		assert.Contains(t, w.Header().Get("Set-Cookie"), "HttpOnly")
		assert.Contains(t, w.Header().Get("Set-Cookie"), "refresh_token")
		assert.Contains(t, w.Header().Get("Set-Cookie"), loginResponse.RefreshToken)
		assert.Equal(t, "Admin", claims.Username)
		assert.Equal(t, "at", token.Header["kid"])
		assert.NotEmptyf(t, loginResponse.AccessToken, "access token is empty")
		assert.NotEmptyf(t, loginResponse.RefreshToken, "refresh token is empty")
	})

	t.Run("invalid username", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		db.On("GetUserByUsername", mock.Anything, "Admin").
			Return(models.User{}, errors.New("no rows found")).Once()

		rdb, _ := redismock.NewClientMock()
		authController := NewAuthenticationController(db, rdb, nil)

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.POST("/login", authController.Login)

		body := bytes.NewBufferString(`{"username": "Admin", "password": "temPass2020@"}`)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("POST", "/login", body)
		r.Header.Set("Content-Type", "application/json")

		e.ServeHTTP(w, r)
		resp := w.Result()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("invalid password", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		db.On("GetUserByUsername", mock.Anything, "Admin").
			Return(models.User{
				ID:       1,
				Username: "Admin",
				Password: "xEDi1V791f7bddc526de7e3b0602d0b2993ce21d",
				TotpKey:  pgtype.Text{String: ""},
			}, nil).Once()

		rdb, _ := redismock.NewClientMock()
		authController := NewAuthenticationController(db, rdb, nil)

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.POST("/login", authController.Login)

		body := bytes.NewBufferString(`{"username": "Admin", "password": "invalid"}`)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("POST", "/login", body)
		r.Header.Set("Content-Type", "application/json")

		e.ServeHTTP(w, r)
		resp := w.Result()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("OTP enabled, should get MFA_REQUIRED status", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		db.On("GetUserByUsername", mock.Anything, "Admin").
			Return(models.User{
				ID:       1,
				Username: "Admin",
				Password: "xEDi1V791f7bddc526de7e3b0602d0b2993ce21d",
				Flags:    flags.UserTotpEnabled,
				TotpKey:  pgtype.Text{String: seed},
			}, nil).Once()

		rdb, _ := redismock.NewClientMock()
		authController := NewAuthenticationController(db, rdb, nil)

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.POST("/login", authController.Login)

		body := bytes.NewBufferString(`{"username": "Admin", "password": "temPass2020@"}`)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("POST", "/login", body)
		r.Header.Set("Content-Type", "application/json")

		e.ServeHTTP(w, r)
		resp := w.Result()

		loginStateResponse := new(loginStateResponse)
		dec := json.NewDecoder(resp.Body)
		if err := dec.Decode(&loginStateResponse); err != nil {
			t.Error("error decoding", err)
		}

		assert.Empty(t, w.Header().Get("Set-Cookie"))
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, loginStateResponse.Status, "MFA_REQUIRED")
		assert.True(t, loginStateResponse.StateToken != "")
	})

	t.Run("invalid request data should throw bad request", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		rdb, _ := redismock.NewClientMock()
		authController := NewAuthenticationController(db, rdb, nil)

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.POST("/login", authController.Login)

		body := bytes.NewBufferString(`{"username": "Admin", "password": 111111}`)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("POST", "/login", body)
		r.Header.Set("Content-Type", "application/json")

		e.ServeHTTP(w, r)
		resp := w.Result()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
}

func TestAuthenticationController_ValidateOTP(t *testing.T) {
	seed := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

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

	// Use the same time throughout the test
	cTime := time.Now()
	timeMock := func() time.Time {
		return cTime
	}
	tokens, _ := helper.GenerateToken(claims, timeMock())
	rt := time.Unix(timeMock().Add(time.Hour*24*7).Unix(), 0)

	t.Run("valid OTP", func(t *testing.T) {
		otp := totp.New(seed, 6, 30, config.ServiceTotpSkew.GetUint8())
		db := mocks.NewQuerier(t)
		db.On("GetUserByID", mock.Anything, int32(1)).
			Return(models.GetUserByIDRow{
				ID:       1,
				Username: "Admin",
				Password: "xEDi1V791f7bddc526de7e3b0602d0b2993ce21d",
				Flags:    flags.UserTotpEnabled,
				TotpKey:  pgtype.Text{String: seed},
			}, nil).Times(2)
		db.On("GetAdminLevel", mock.Anything, int32(1)).
			Return(models.GetAdminLevelRow{}, nil).Once()
		db.On("ListUserRoles", mock.Anything, int32(1)).
			Return([]models.Role{}, nil).Once()

		rdb, rmock := redismock.NewClientMock()

		checks.InitUser(context.Background(), db)
		authController := NewAuthenticationController(db, rdb, timeMock)

		state, _ := authController.createStateToken(context.TODO(), 1)
		stateKey := fmt.Sprintf("user:mfa:state:%s", state)
		rmock.Regexp().ExpectGet("user:mfa:state:.*").SetVal("1")
		rmock.ExpectDel(stateKey).SetVal(1)
		rmock.Regexp().ExpectSet("user:1:rt:", `.*`, rt.Sub(timeMock())).SetVal("1")

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.POST("/validate-otp", authController.VerifyFactor)

		body := bytes.NewBufferString(fmt.Sprintf(`{"state_token": "%s", "otp": "%s"}`, state, otp.Generate()))
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("POST", "/validate-otp", body)
		r.Header.Set("Content-Type", "application/json")

		e.ServeHTTP(w, r)
		resp := w.Result()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		err := rmock.ExpectationsWereMet()
		assert.Equal(t, nil, err)
		rmock.ClearExpect()

		loginResponse := new(LoginResponse)
		dec := json.NewDecoder(resp.Body)
		if err := dec.Decode(&loginResponse); err != nil {
			t.Error("error decoding", err)
		}

		token, err := jwt.ParseWithClaims(
			loginResponse.AccessToken,
			&helper.JwtClaims{},
			func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, errors.New("unexpected signing method")
				}
				return []byte(config.ServiceJWTSigningSecret.GetString()), nil
			},
		)
		if err != nil {
			t.Error("error parsing token", err)
		}
		c := token.Claims.(*helper.JwtClaims)

		assert.Contains(t, w.Header().Get("Set-Cookie"), "HttpOnly")
		assert.Contains(t, w.Header().Get("Set-Cookie"), "refresh_token")
		assert.Contains(t, w.Header().Get("Set-Cookie"), loginResponse.RefreshToken)
		assert.NotEmptyf(t, loginResponse.AccessToken, "access token is empty: %s", loginResponse.AccessToken)
		assert.NotEmptyf(t, loginResponse.RefreshToken, "refresh token is empty: %s", loginResponse.RefreshToken)
		assert.Equal(t, c.Username, "Admin")
	})

	t.Run("invalid OTP", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		db.On("GetUserByID", mock.Anything, int32(1)).
			Return(models.GetUserByIDRow{
				ID:       1,
				Username: "Admin",
				Password: "xEDi1V791f7bddc526de7e3b0602d0b2993ce21d",
				Flags:    flags.UserTotpEnabled,
				TotpKey:  pgtype.Text{String: seed},
			}, nil).Once()

		rdb, rmock := redismock.NewClientMock()
		rmock.ExpectGet("user:mfa:state:test").SetVal("1")
		rmock.ExpectDel("user:mfa:state:test").SetVal(1)
		authController := NewAuthenticationController(db, rdb, nil)

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.POST("/validate-otp", authController.VerifyFactor)

		body := bytes.NewBufferString(fmt.Sprintf(`{"state_token": "test", "otp": "%s"}`, "111111"))
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("POST", "/validate-otp", body)
		r.Header.Set("Content-Type", "application/json")

		e.ServeHTTP(w, r)
		resp := w.Result()

		otpResponse := new(customError)
		dec := json.NewDecoder(resp.Body)
		if err := dec.Decode(&otpResponse); err != nil {
			t.Error("error decoding", err)
		}

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		assert.Contains(t, otpResponse.Message, "invalid OTP")
	})

	t.Run("broken OTP", func(t *testing.T) {
		db := mocks.NewQuerier(t)

		rdb, _ := redismock.NewClientMock()
		authController := NewAuthenticationController(db, rdb, nil)

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.POST("/validate-otp", authController.VerifyFactor, echojwt.WithConfig(jwtConfig))

		body := bytes.NewBufferString(fmt.Sprintf(`{"otp": "%s"}`, "aaaaaa"))
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("POST", "/validate-otp", body)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokens.AccessToken))

		e.ServeHTTP(w, r)
		resp := w.Result()

		otpResponse := new(customError)
		dec := json.NewDecoder(resp.Body)
		if err := dec.Decode(&otpResponse); err != nil {
			t.Error("error decoding", err)
		}
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Contains(t, otpResponse.Message, "otp must be a valid numeric")
	})

	t.Run("invalid request data should throw BadRequest", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		rdb, _ := redismock.NewClientMock()
		authController := NewAuthenticationController(db, rdb, nil)

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.POST("/validate-otp", authController.VerifyFactor, echojwt.WithConfig(jwtConfig))

		body := bytes.NewBufferString(`{"otp": 11111}`)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("POST", "/validate-otp", body)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokens.AccessToken))

		e.ServeHTTP(w, r)
		resp := w.Result()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("missing state token should throw an error", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		rdb, _ := redismock.NewClientMock()
		authController := NewAuthenticationController(db, rdb, nil)

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.POST("/validate-otp", authController.VerifyFactor, echojwt.WithConfig(jwtConfig))

		body := bytes.NewBufferString(fmt.Sprintf(`{"otp": "%s"}`, "111111"))
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("POST", "/validate-otp", body)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokens.AccessToken))

		e.ServeHTTP(w, r)
		resp := w.Result()

		otpResponse := new(customError)
		dec := json.NewDecoder(resp.Body)
		if err := dec.Decode(&otpResponse); err != nil {
			t.Error("error decoding", err)
		}
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Equal(t, "state_token is a required field", otpResponse.Message)
	})

	t.Run("should return error on a too long username", func(t *testing.T) {
		db := mocks.NewQuerier(t)

		rdb, _ := redismock.NewClientMock()
		authController := NewAuthenticationController(db, rdb, nil)

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.POST("/login", authController.Login)

		body := bytes.NewBufferString(`{"username": "Adminadminadmin", "password": "temPass2020@"}`)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("POST", "/login", body)
		r.Header.Set("Content-Type", "application/json")

		e.ServeHTTP(w, r)
		resp := w.Result()

		cErr := new(customError)
		dec := json.NewDecoder(resp.Body)
		if err := dec.Decode(&cErr); err != nil {
			t.Error("error decoding", err)
		}

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Contains(t, cErr.Message, "maximum of 12 characters")
	})
}

func TestAuthenticationController_Logout(t *testing.T) {
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
	tokens, _ := helper.GenerateToken(claims, time.Now())

	t.Run("should logout user", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		rdb, rmock := redismock.NewClientMock()
		authController := NewAuthenticationController(db, rdb, nil)

		rmock.ExpectDel(fmt.Sprintf("user:%d:rt:%s", claims.UserID, tokens.RefreshUUID)).SetVal(1)

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.POST("/logout", authController.Logout, echojwt.WithConfig(jwtConfig))

		w := httptest.NewRecorder()
		r, _ := http.NewRequest("POST", "/logout", nil)
		r.Header.Add("Authorization", fmt.Sprintf("Bearer %s", tokens.AccessToken))
		r.Header.Add("Cookie", "refresh_token=faketoken")

		e.ServeHTTP(w, r)
		resp := w.Result()

		if err := rmock.ExpectationsWereMet(); err != nil {
			t.Error(err)
		}
		rmock.ClearExpect()

		assert.Equal(t, resp.Cookies()[0].Expires, time.Date(1, time.January, 1, 0, 0, 0, 0, time.UTC))
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("should throw bad request on incorrect input", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		rdb, _ := redismock.NewClientMock()
		authController := NewAuthenticationController(db, rdb, nil)

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.POST("/logout", authController.Logout, echojwt.WithConfig(jwtConfig))
		body := bytes.NewBufferString(`{"logout_all": 11111}`)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("POST", "/logout", body)
		r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokens.AccessToken))

		e.ServeHTTP(w, r)
		resp := w.Result()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("missing bearer token should return 400", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		rdb, _ := redismock.NewClientMock()
		authController := NewAuthenticationController(db, rdb, nil)

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.POST("/logout", authController.Logout, echojwt.WithConfig(jwtConfig))

		w := httptest.NewRecorder()
		r, _ := http.NewRequest("POST", "/logout", nil)

		e.ServeHTTP(w, r)
		resp := w.Result()

		errResponse := new(customError)
		dec := json.NewDecoder(resp.Body)
		if err := dec.Decode(&errResponse); err != nil {
			t.Error("error decoding", err)
		}
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Contains(t, errResponse.Message, "missing or malformed jwt")
	})

	t.Run("should return status unauthorized if refresh key does not exist", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		rdb, rmock := redismock.NewClientMock()
		authController := NewAuthenticationController(db, rdb, nil)
		rmock.ExpectDel(fmt.Sprintf("user:%d:rt:%s", claims.UserID, tokens.RefreshUUID)).
			SetErr(errors.New("redis error"))

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.POST("/logout", authController.Logout, echojwt.WithConfig(jwtConfig))

		w := httptest.NewRecorder()
		r, _ := http.NewRequest("POST", "/logout", nil)
		r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokens.AccessToken))

		e.ServeHTTP(w, r)
		resp := w.Result()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})
}

func TestAuthenticationController_Redis(t *testing.T) {
	config.DefaultConfig()

	claims := new(helper.JwtClaims)
	claims.UserID = 1
	claims.Username = "Admin"
	tokens, _ := helper.GenerateToken(claims, time.Now())

	t.Run("should create redis entry", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		rdb, rmock := redismock.NewClientMock()
		rt := time.Unix(tokens.RtExpires.Unix(), 0)
		n := time.Now()
		timeMock := func() time.Time {
			return n
		}

		key := fmt.Sprintf("user:%d:rt:%s", claims.UserID, tokens.RefreshUUID)
		rmock.ExpectSet(key, strconv.Itoa(int(claims.UserID)), rt.Sub(n)).SetVal("1")
		authController := NewAuthenticationController(db, rdb, timeMock)
		err := authController.storeRefreshToken(context.Background(), 1, tokens)
		if err != nil {
			t.Error("error storing refresh token", err)
		}
		if err := rmock.ExpectationsWereMet(); err != nil {
			t.Error(err)
		}
		rmock.ClearExpect()
	})

	t.Run("should delete redis entry", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		rdb, rmock := redismock.NewClientMock()

		key := fmt.Sprintf("user:%d:rt:%s", claims.UserID, tokens.RefreshUUID)
		rmock.ExpectDel(key).SetVal(1)
		authController := NewAuthenticationController(db, rdb, nil)
		deleted, err := authController.deleteRefreshToken(context.Background(), 1, tokens.RefreshUUID, false)
		if err != nil && deleted == 0 {
			t.Error("error deleting refresh token", err)
		}
		if err := rmock.ExpectationsWereMet(); err != nil {
			t.Error(err)
		}
		rmock.ClearExpect()
	})

	t.Run("should delete all redis entries for one user", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		rdb, rmock := redismock.NewClientMock()

		key := fmt.Sprintf("user:%d:rt:*", claims.UserID)
		rmock.ExpectDel(key).SetVal(1)
		authController := NewAuthenticationController(db, rdb, nil)
		deleted, err := authController.deleteRefreshToken(context.Background(), 1, tokens.RefreshUUID, true)
		if err != nil && deleted == 0 {
			t.Error("error deleting refresh token", err)
		}
		if err := rmock.ExpectationsWereMet(); err != nil {
			t.Error(err)
		}
		rmock.ClearExpect()
	})

	t.Run("redis should throw an error on storing key", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		rdb, rmock := redismock.NewClientMock()
		rt := time.Unix(tokens.RtExpires.Unix(), 0)
		n := time.Now()
		timeMock := func() time.Time {
			return n
		}
		key := fmt.Sprintf("user:%d:rt:%s", claims.UserID, tokens.RefreshUUID)
		rmock.ExpectSet(key, strconv.Itoa(int(claims.UserID)), rt.Sub(n)).SetErr(errors.New("redis error"))

		authController := NewAuthenticationController(db, rdb, timeMock)
		err := authController.storeRefreshToken(context.Background(), 1, tokens)
		assert.Equal(t, err.Error(), "redis error")

		if err := rmock.ExpectationsWereMet(); err != nil {
			t.Error(err)
		}
		rmock.ClearExpect()
	})

	t.Run("redis should throw an error on delete", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		rdb, rmock := redismock.NewClientMock()
		key := fmt.Sprintf("user:%d:rt:%s", claims.UserID, tokens.RefreshUUID)
		rmock.ExpectDel(key).SetErr(errors.New("redis error"))

		authController := NewAuthenticationController(db, rdb, nil)
		deleted, err := authController.deleteRefreshToken(context.Background(), 1, tokens.RefreshUUID, false)

		assert.Equal(t, err.Error(), "redis error")
		assert.Equal(t, int64(0), deleted)

		if err := rmock.ExpectationsWereMet(); err != nil {
			t.Error(err)
		}
		rmock.ClearExpect()
	})
}

func TestAuthenticationController_RefreshToken(t *testing.T) {
	config.DefaultConfig()

	claims := new(helper.JwtClaims)
	claims.UserID = 1
	claims.Username = "Admin"
	n := time.Now()
	tokens, _ := helper.GenerateToken(claims, n)
	timeMock := func() time.Time {
		return n
	}

	t.Run("request a new pair of tokens using a valid refresh token", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		db.On("GetUserByID", mock.Anything, int32(1)).
			Return(models.GetUserByIDRow{ID: 1, Username: "Admin"}, nil).
			Once()
		rdb, rmock := redismock.NewClientMock()
		rt := time.Unix(tokens.RtExpires.Unix(), 0)
		key := fmt.Sprintf("user:%d:rt:%s", claims.UserID, tokens.RefreshUUID)
		rmock.ExpectSet(key, strconv.Itoa(int(claims.UserID)), rt.Sub(n)).SetVal("1")
		rmock.ExpectDel(key).SetVal(1)
		rmock.Regexp().ExpectSet("user:1:rt:", `.*`, rt.Sub(n)).SetVal("1")

		authController := NewAuthenticationController(db, rdb, timeMock)
		err := authController.storeRefreshToken(context.Background(), 1, tokens)
		assert.NoError(t, err, "error storing refresh token")

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.POST("/token/refresh", authController.RefreshToken)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("POST", "/token/refresh", nil)
		r.Header.Add("Content-Type", "application/json")
		r.Header.Add("Cookie", "refresh_token="+tokens.RefreshToken)

		e.ServeHTTP(w, r)
		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		if err := rmock.ExpectationsWereMet(); err != nil {
			t.Error(err)
		}
		rmock.ClearExpect()

		response := new(LoginResponse)
		dec := json.NewDecoder(resp.Body)
		if err := dec.Decode(&response); err != nil {
			t.Error("error decoding", err)
		}

		token, err := jwt.ParseWithClaims(
			response.AccessToken,
			&helper.JwtClaims{},
			func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, errors.New("unexpected signing method")
				}
				return []byte(config.ServiceJWTSigningSecret.GetString()), nil
			},
		)
		assert.NoError(t, err, "error parsing token")
		c := token.Claims.(*helper.JwtClaims)

		assert.Contains(t, w.Header().Get("Set-Cookie"), "HttpOnly")
		assert.Contains(t, w.Header().Get("Set-Cookie"), "refresh_token")
		assert.Contains(t, w.Header().Get("Set-Cookie"), response.RefreshToken)
		assert.NotEmptyf(t, response.AccessToken, "access token is empty: %s", response.AccessToken)
		assert.NotEmptyf(t, response.RefreshToken, "refresh token is empty: %s", response.RefreshToken)
		assert.Equal(t, c.Username, "Admin")
	})

	t.Run("using an expired refresh token should return 401", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		rdb, _ := redismock.NewClientMock()

		authController := NewAuthenticationController(db, rdb, nil)
		expiredTokens, _ := helper.GenerateToken(claims, time.Now().Add(-time.Hour*24*8))
		e := echo.New()
		e.Validator = helper.NewValidator()
		e.POST("/token/refresh", authController.RefreshToken)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("POST", "/token/refresh", nil)
		r.Header.Add("Content-Type", "application/json")
		r.Header.Add("Cookie", "refresh_token="+expiredTokens.RefreshToken)

		e.ServeHTTP(w, r)
		resp := w.Result()

		cErr := new(customError)
		dec := json.NewDecoder(resp.Body)
		assert.NoError(t, dec.Decode(&cErr), "error decoding")
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		assert.Equal(t, "refresh token expired", cErr.Message)
	})

	t.Run("missing refresh_token cookie should return 401", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		rdb, _ := redismock.NewClientMock()

		authController := NewAuthenticationController(db, rdb, nil)
		e := echo.New()
		e.Validator = helper.NewValidator()
		e.POST("/token/refresh", authController.RefreshToken)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("POST", "/token/refresh", nil)
		r.Header.Add("Content-Type", "application/json")

		e.ServeHTTP(w, r)
		resp := w.Result()

		cErr := new(customError)
		dec := json.NewDecoder(resp.Body)
		assert.NoError(t, dec.Decode(&cErr), "error decoding")
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})
}
