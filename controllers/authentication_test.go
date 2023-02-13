// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

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
	"testing"
	"time"

	"github.com/undernetirc/cservice-api/db/types/flags"

	"github.com/go-redis/redismock/v9"
	"github.com/golang-jwt/jwt/v4"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/undernetirc/cservice-api/db/mocks"
	"github.com/undernetirc/cservice-api/internal/auth/oath/totp"
	"github.com/undernetirc/cservice-api/internal/config"
	"github.com/undernetirc/cservice-api/internal/helper"
	"github.com/undernetirc/cservice-api/models"
)

func TestAuthenticationController_Login(t *testing.T) {
	seed := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

	config.Conf = &config.Config{}
	config.Conf.JWT.SigningMethod = "HS256"
	config.Conf.JWT.SigningKey = "hirkumpirkum"
	config.Conf.Redis.EnableMultiLogout = false

	t.Run("valid login without OTP", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		db.On("GetUserByUsername", mock.Anything, "Admin").
			Return(models.User{
				ID:       1,
				UserName: "Admin",
				Password: "xEDi1V791f7bddc526de7e3b0602d0b2993ce21d",
				TotpKey:  new(string),
			}, nil).Once()

		rdb, _ := redismock.NewClientMock()

		authController := NewAuthenticationController(db, rdb)

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

		loginResponse := new(loginResponse)
		dec := json.NewDecoder(resp.Body)
		if err := dec.Decode(&loginResponse); err != nil {
			t.Error("error decoding", err)
		}

		token, err := jwt.ParseWithClaims(loginResponse.AccessToken, &helper.JwtClaims{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, errors.New("unexpected signing method")
			}
			return []byte(config.Conf.JWT.SigningKey), nil
		})
		if err != nil {
			t.Error("error parsing token", err)
		}

		claims := token.Claims.(*helper.JwtClaims)

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
		authController := NewAuthenticationController(db, rdb)

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
				UserName: "Admin",
				Password: "xEDi1V791f7bddc526de7e3b0602d0b2993ce21d",
				TotpKey:  new(string),
			}, nil).Once()

		rdb, _ := redismock.NewClientMock()
		authController := NewAuthenticationController(db, rdb)

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
				UserName: "Admin",
				Password: "xEDi1V791f7bddc526de7e3b0602d0b2993ce21d",
				Flags:    flags.USER_TOTP_ENABLED,
				TotpKey:  &seed,
			}, nil).Once()

		rdb, _ := redismock.NewClientMock()
		authController := NewAuthenticationController(db, rdb)

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

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, loginStateResponse.Status, "MFA_REQUIRED")
		assert.True(t, loginStateResponse.StateToken != "")
	})

	t.Run("invalid request data should throw bad request", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		rdb, _ := redismock.NewClientMock()
		authController := NewAuthenticationController(db, rdb)

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

	config.Conf = &config.Config{}
	config.Conf.JWT.SigningMethod = "HS256"
	config.Conf.JWT.SigningKey = "hirkumpirkum"
	jwtConfig := echojwt.Config{
		SigningMethod: config.Conf.JWT.SigningMethod,
		SigningKey:    config.Conf.GetJWTPublicKey(),
		NewClaimsFunc: func(c echo.Context) jwt.Claims {
			return new(helper.JwtClaims)
		},
	}

	claims := new(helper.JwtClaims)
	claims.UserId = 1
	claims.Username = "Admin"
	tokens, _ := helper.GenerateToken(claims)

	t.Run("valid OTP", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		db.On("GetUserByID", mock.Anything, int32(1)).
			Return(models.GetUserByIDRow{
				ID:       1,
				UserName: "Admin",
				Password: "xEDi1V791f7bddc526de7e3b0602d0b2993ce21d",
				Flags:    flags.USER_TOTP_ENABLED,
				TotpKey:  &seed,
			}, nil).Once()

		rdb, rmock := redismock.NewClientMock()
		rmock.ExpectGet("user:mfa:state:test").SetVal("1")
		rmock.ExpectDel("user:mfa:state:test").SetVal(1)

		authController := NewAuthenticationController(db, rdb)

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.POST("/validate-otp", authController.VerifyFactor)

		otp := totp.New(seed, 6, 30)
		body := bytes.NewBufferString(fmt.Sprintf(`{"state_token": "test", "otp": "%s"}`, otp.Generate()))
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("POST", "/validate-otp", body)
		r.Header.Set("Content-Type", "application/json")

		e.ServeHTTP(w, r)
		resp := w.Result()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		loginResponse := new(loginResponse)
		dec := json.NewDecoder(resp.Body)
		if err := dec.Decode(&loginResponse); err != nil {
			t.Error("error decoding", err)
		}

		token, err := jwt.ParseWithClaims(loginResponse.AccessToken, &helper.JwtClaims{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, errors.New("unexpected signing method")
			}
			return []byte(config.Conf.JWT.SigningKey), nil
		})
		if err != nil {
			t.Error("error parsing token", err)
		}
		c := token.Claims.(*helper.JwtClaims)

		if err := rmock.ExpectationsWereMet(); err != nil {
			t.Error(err)
		}
		rmock.ClearExpect()

		assert.NotEmptyf(t, loginResponse.AccessToken, "access token is empty: %s", loginResponse.AccessToken)
		assert.NotEmptyf(t, loginResponse.RefreshToken, "refresh token is empty: %s", loginResponse.RefreshToken)
		assert.Equal(t, c.Username, "Admin")
	})

	t.Run("invalid OTP", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		db.On("GetUserByID", mock.Anything, int32(1)).
			Return(models.GetUserByIDRow{
				ID:       1,
				UserName: "Admin",
				Password: "xEDi1V791f7bddc526de7e3b0602d0b2993ce21d",
				Flags:    flags.USER_TOTP_ENABLED,
				TotpKey:  &seed,
			}, nil).Once()

		rdb, rmock := redismock.NewClientMock()
		rmock.ExpectGet("user:mfa:state:test").SetVal("1")
		rmock.ExpectDel("user:mfa:state:test").SetVal(1)
		authController := NewAuthenticationController(db, rdb)

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
		authController := NewAuthenticationController(db, rdb)

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
		assert.Contains(t, otpResponse.Message, "OTP must be a valid numeric")
	})

	t.Run("invalid request data should throw BadRequest", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		rdb, _ := redismock.NewClientMock()
		authController := NewAuthenticationController(db, rdb)

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
		authController := NewAuthenticationController(db, rdb)

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
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		assert.Equal(t, "Invalid or expired state token", otpResponse.Message)
	})

	t.Run("should return error on a too long username", func(t *testing.T) {
		db := mocks.NewQuerier(t)

		rdb, _ := redismock.NewClientMock()
		authController := NewAuthenticationController(db, rdb)

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
	config.Conf = &config.Config{}
	config.Conf.JWT.SigningMethod = "HS256"
	config.Conf.JWT.SigningKey = "hirkumpirkum"
	config.Conf.JWT.RefreshSigningKey = "hirkumpirkum"
	config.Conf.Redis.EnableMultiLogout = true

	jwtConfig := echojwt.Config{
		SigningMethod: config.Conf.JWT.SigningMethod,
		SigningKey:    config.Conf.GetJWTPublicKey(),
		NewClaimsFunc: func(c echo.Context) jwt.Claims {
			return new(helper.JwtClaims)
		},
	}

	claims := new(helper.JwtClaims)
	claims.UserId = 1
	claims.Username = "Admin"
	tokens, _ := helper.GenerateToken(claims)

	t.Run("should logout user", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		rdb, rmock := redismock.NewClientMock()
		authController := NewAuthenticationController(db, rdb)

		rmock.ExpectDel(fmt.Sprintf("user:%d:rt:%s", claims.UserId, tokens.RefreshUUID)).SetVal(1)

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.POST("/logout", authController.Logout, echojwt.WithConfig(jwtConfig))

		w := httptest.NewRecorder()
		r, _ := http.NewRequest("POST", "/logout", nil)
		r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokens.AccessToken))

		e.ServeHTTP(w, r)
		resp := w.Result()

		if err := rmock.ExpectationsWereMet(); err != nil {
			t.Error(err)
		}
		rmock.ClearExpect()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("should throw bad request on incorrect input", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		rdb, _ := redismock.NewClientMock()
		authController := NewAuthenticationController(db, rdb)

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

	t.Run("missing bearer token should return 401", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		rdb, _ := redismock.NewClientMock()
		authController := NewAuthenticationController(db, rdb)

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
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		assert.Contains(t, errResponse.Message, "missing or malformed jwt")
	})

	t.Run("should return status unauthorized if refresh key does not exist", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		rdb, rmock := redismock.NewClientMock()
		authController := NewAuthenticationController(db, rdb)
		rmock.ExpectDel(fmt.Sprintf("user:%d:rt:%s", claims.UserId, tokens.RefreshUUID)).SetErr(errors.New("redis error"))

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
	config.Conf = &config.Config{}
	config.Conf.JWT.SigningMethod = "HS256"
	config.Conf.JWT.SigningKey = "hirkumpirkum"
	config.Conf.JWT.RefreshSigningKey = "hirkumpirkum"
	config.Conf.Redis.EnableMultiLogout = true

	claims := new(helper.JwtClaims)
	claims.UserId = 1
	claims.Username = "Admin"
	tokens, _ := helper.GenerateToken(claims)

	t.Run("should create redis entry", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		rdb, rmock := redismock.NewClientMock()
		rt := time.Unix(tokens.RtExpires.Unix(), 0)
		now := time.Now()

		key := fmt.Sprintf("user:%d:rt:%s", claims.UserId, tokens.RefreshUUID)
		rmock.ExpectSet(key, strconv.Itoa(int(claims.UserId)), rt.Sub(now)).SetVal("1")
		authController := NewAuthenticationController(db, rdb)
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

		key := fmt.Sprintf("user:%d:rt:%s", claims.UserId, tokens.RefreshUUID)
		rmock.ExpectDel(key).SetVal(1)
		authController := NewAuthenticationController(db, rdb)
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

		key := fmt.Sprintf("user:%d:rt:*", claims.UserId)
		rmock.ExpectDel(key).SetVal(1)
		authController := NewAuthenticationController(db, rdb)
		deleted, err := authController.deleteRefreshToken(context.Background(), 1, tokens.RefreshUUID, true)
		if err != nil && deleted == 0 {
			t.Error("error deleting refresh token", err)
		}
		if err := rmock.ExpectationsWereMet(); err != nil {
			t.Error(err)
		}
		rmock.ClearExpect()
	})

	t.Run("should not create redis entry when EnableMultiLogout is false", func(t *testing.T) {
		config.Conf.Redis.EnableMultiLogout = false
		db := mocks.NewQuerier(t)
		rdb, rmock := redismock.NewClientMock()
		authController := NewAuthenticationController(db, rdb)
		err := authController.storeRefreshToken(context.Background(), 1, tokens)
		if err != nil {
			t.Error("error storing refresh token", err)
		}
		if err := rmock.ExpectationsWereMet(); err != nil {
			t.Error(err)
		}
		rmock.ClearExpect()
	})

	t.Run("should return 1 deleted entry when EnableMultiLogout is false", func(t *testing.T) {
		config.Conf.Redis.EnableMultiLogout = false
		db := mocks.NewQuerier(t)
		rdb, rmock := redismock.NewClientMock()
		authController := NewAuthenticationController(db, rdb)
		deleted, err := authController.deleteRefreshToken(context.Background(), 1, tokens.RefreshUUID, false)
		if err != nil && deleted == 0 {
			t.Error("error storing refresh token", err)
		}
		if err := rmock.ExpectationsWereMet(); err != nil {
			t.Error(err)
		}
		rmock.ClearExpect()
	})

	t.Run("redis should throw an error on storing key", func(t *testing.T) {
		config.Conf.Redis.EnableMultiLogout = true
		db := mocks.NewQuerier(t)
		rdb, rmock := redismock.NewClientMock()
		rt := time.Unix(tokens.RtExpires.Unix(), 0)
		now := time.Now()
		key := fmt.Sprintf("user:%d:rt:%s", claims.UserId, tokens.RefreshUUID)
		rmock.ExpectSet(key, strconv.Itoa(int(claims.UserId)), rt.Sub(now)).SetErr(errors.New("redis error"))

		authController := NewAuthenticationController(db, rdb)
		err := authController.storeRefreshToken(context.Background(), 1, tokens)
		assert.Equal(t, err.Error(), "redis error")

		if err := rmock.ExpectationsWereMet(); err != nil {
			t.Error(err)
		}
		rmock.ClearExpect()
	})

	t.Run("redis should throw an error on delete", func(t *testing.T) {
		config.Conf.Redis.EnableMultiLogout = true
		db := mocks.NewQuerier(t)
		rdb, rmock := redismock.NewClientMock()
		key := fmt.Sprintf("user:%d:rt:%s", claims.UserId, tokens.RefreshUUID)
		rmock.ExpectDel(key).SetErr(errors.New("redis error"))

		authController := NewAuthenticationController(db, rdb)
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
	config.Conf = &config.Config{}
	config.Conf.JWT.SigningMethod = "HS256"
	config.Conf.JWT.SigningKey = "hirkumpirkum"
	config.Conf.JWT.RefreshSigningKey = "hirkumpirkum"
	config.Conf.Redis.EnableMultiLogout = false

	claims := new(helper.JwtClaims)
	claims.UserId = 1
	claims.Username = "Admin"
	tokens, _ := helper.GenerateToken(claims)

	t.Run("request a new pair of tokens using a valid refresh token", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		db.On("GetUserByID", mock.Anything, int32(1)).
			Return(models.GetUserByIDRow{ID: 1, UserName: "Admin"}, nil).
			Once()
		rdb, _ := redismock.NewClientMock()

		authController := NewAuthenticationController(db, rdb)

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.POST("/token/refresh", authController.RefreshToken)
		body := bytes.NewBufferString(fmt.Sprintf(`{"refresh_token": "%s"}`, tokens.RefreshToken))
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("POST", "/token/refresh", body)
		r.Header.Set("Content-Type", "application/json")

		e.ServeHTTP(w, r)
		resp := w.Result()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		response := new(loginResponse)
		dec := json.NewDecoder(resp.Body)
		if err := dec.Decode(&response); err != nil {
			t.Error("error decoding", err)
		}

		token, err := jwt.ParseWithClaims(response.AccessToken, &helper.JwtClaims{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, errors.New("unexpected signing method")
			}
			return []byte(config.Conf.JWT.SigningKey), nil
		})
		if err != nil {
			t.Error("error parsing token", err)
		}
		c := token.Claims.(*helper.JwtClaims)

		assert.NotEmptyf(t, response.AccessToken, "access token is empty: %s", response.AccessToken)
		assert.NotEmptyf(t, response.RefreshToken, "refresh token is empty: %s", response.RefreshToken)
		assert.Equal(t, c.Username, "Admin")
	})
}
