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
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/undernetirc/cservice-api/db/mocks"
	"github.com/undernetirc/cservice-api/db/types/flags"
	"github.com/undernetirc/cservice-api/internal/auth/backupcodes"
	"github.com/undernetirc/cservice-api/internal/auth/oath/totp"
	"github.com/undernetirc/cservice-api/internal/checks"
	"github.com/undernetirc/cservice-api/internal/config"
	apierrors "github.com/undernetirc/cservice-api/internal/errors"
	"github.com/undernetirc/cservice-api/internal/helper"
	"github.com/undernetirc/cservice-api/models"
)

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
		db.On("GetUser", mock.Anything, models.GetUserParams{Username: "Admin"}).
			Return(models.GetUserRow{
				ID:       1,
				Username: "Admin",
				Password: "xEDi1V791f7bddc526de7e3b0602d0b2993ce21d",
				TotpKey:  pgtype.Text{String: "", Valid: true},
			}, nil).Once()
		db.On("GetUser", mock.Anything, models.GetUserParams{ID: int32(1)}).
			Return(models.GetUserRow{
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
		db.On("GetUser", mock.Anything, models.GetUserParams{Username: "Admin"}).
			Return(models.GetUserRow{}, errors.New("no rows found")).Once()

		rdb, _ := redismock.NewClientMock()
		checks.InitUser(context.Background(), db)
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
		db.On("GetUser", mock.Anything, models.GetUserParams{Username: "Admin"}).
			Return(models.GetUserRow{
				ID:       1,
				Username: "Admin",
				Password: "xEDi1V791f7bddc526de7e3b0602d0b2993ce21d",
				TotpKey:  pgtype.Text{String: ""},
			}, nil).Once()

		rdb, _ := redismock.NewClientMock()
		checks.InitUser(context.Background(), db)
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
		db.On("GetUser", mock.Anything, models.GetUserParams{Username: "Admin"}).
			Return(models.GetUserRow{
				ID:       1,
				Username: "Admin",
				Password: "xEDi1V791f7bddc526de7e3b0602d0b2993ce21d",
				Flags:    flags.UserTotpEnabled,
				TotpKey:  pgtype.Text{String: seed},
			}, nil).Once()

		rdb, _ := redismock.NewClientMock()
		checks.InitUser(context.Background(), db)
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
		checks.InitUser(context.Background(), db)
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
		db.On("GetUser", mock.Anything, models.GetUserParams{ID: int32(1)}).
			Return(models.GetUserRow{
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
		db.On("GetUser", mock.Anything, models.GetUserParams{ID: int32(1)}).
			Return(models.GetUserRow{
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

		var otpResponse apierrors.ErrorResponse
		dec := json.NewDecoder(resp.Body)
		if err := dec.Decode(&otpResponse); err != nil {
			t.Error("error decoding", err)
		}

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		assert.Contains(t, otpResponse.Error.Message, "Invalid OTP")
	})

	t.Run("broken OTP", func(t *testing.T) {
		db := mocks.NewQuerier(t)

		rdb, _ := redismock.NewClientMock()
		authController := NewAuthenticationController(db, rdb, nil)

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.POST("/validate-otp", authController.VerifyFactor, echojwt.WithConfig(jwtConfig))

		body := bytes.NewBufferString(fmt.Sprintf(`{"state_token": "test", "otp": "%s"}`, "aaaaaa"))
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("POST", "/validate-otp", body)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokens.AccessToken))

		e.ServeHTTP(w, r)
		resp := w.Result()

		var otpResponse apierrors.ErrorResponse
		dec := json.NewDecoder(resp.Body)
		if err := dec.Decode(&otpResponse); err != nil {
			t.Error("error decoding", err)
		}
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Contains(t, otpResponse.Error.Message, "OTP must be either 6 digits (TOTP) or backup code format")
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

		var otpResponse apierrors.ErrorResponse
		dec := json.NewDecoder(resp.Body)
		if err := dec.Decode(&otpResponse); err != nil {
			t.Error("error decoding", err)
		}
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Equal(t, "state_token is a required field", otpResponse.Error.Message)
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

		var errorResp apierrors.ErrorResponse
		dec := json.NewDecoder(resp.Body)
		if err := dec.Decode(&errorResp); err != nil {
			t.Error("error decoding", err)
		}

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Contains(t, errorResp.Error.Message, "maximum of 12 characters")
	})
}

func TestAuthenticationController_VerifyFactorInputValidation(t *testing.T) {
	seed := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	config.DefaultConfig()

	t.Run("test input validation accepts backup code format", func(t *testing.T) {
		db := mocks.NewServiceInterface(t)
		db.On("GetUser", mock.Anything, models.GetUserParams{ID: int32(1)}).
			Return(models.GetUserRow{
				ID:       1,
				Username: "Admin",
				Flags:    flags.UserTotpEnabled,
				TotpKey:  pgtype.Text{String: seed},
			}, nil).Once()

		// Mock no backup codes available so backup code fails
		db.On("GetUserBackupCodes", mock.Anything, int32(1)).
			Return(models.GetUserBackupCodesRow{
				BackupCodes: []byte{}, // Empty backup codes
			}, nil).Once()

		rdb, rmock := redismock.NewClientMock()
		rmock.ExpectGet("user:mfa:state:test").SetVal("1")
		rmock.ExpectDel("user:mfa:state:test").SetVal(1)
		authController := NewAuthenticationController(db, rdb, nil)

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.POST("/validate-otp", authController.VerifyFactor)

		// Test that backup code format passes validation
		body := bytes.NewBufferString(`{"state_token": "test", "otp": "abcde-12345"}`)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("POST", "/validate-otp", body)
		r.Header.Set("Content-Type", "application/json")

		e.ServeHTTP(w, r)
		resp := w.Result()

		// Should not be a validation error (400), should be auth error (401) since no backup codes
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("test input validation rejects invalid format", func(t *testing.T) {
		db := mocks.NewServiceInterface(t)
		rdb, rmock := redismock.NewClientMock()
		rmock.ExpectGet("user:mfa:state:test").SetVal("1")
		rmock.ExpectDel("user:mfa:state:test").SetVal(1)
		authController := NewAuthenticationController(db, rdb, nil)

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.POST("/validate-otp", authController.VerifyFactor)

		// Test with malformed backup code (wrong length)
		body := bytes.NewBufferString(`{"state_token": "test", "otp": "abc-123"}`)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("POST", "/validate-otp", body)
		r.Header.Set("Content-Type", "application/json")

		e.ServeHTTP(w, r)
		resp := w.Result()

		var otpResponse apierrors.ErrorResponse
		dec := json.NewDecoder(resp.Body)
		if err := dec.Decode(&otpResponse); err != nil {
			t.Error("error decoding", err)
		}

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Contains(t, otpResponse.Error.Message, "OTP must be either 6 digits (TOTP) or backup code format")
	})

	t.Run("test TOTP still works with enhanced validation", func(t *testing.T) {
		otp := totp.New(seed, 6, 30, config.ServiceTotpSkew.GetUint8())

		cTime := time.Now()
		timeMock := func() time.Time {
			return cTime
		}
		rt := time.Unix(timeMock().Add(time.Hour*24*7).Unix(), 0)

		db := mocks.NewServiceInterface(t)
		db.On("GetUser", mock.Anything, models.GetUserParams{ID: int32(1)}).
			Return(models.GetUserRow{
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

		// Test that TOTP still works with enhanced validation
		body := bytes.NewBufferString(fmt.Sprintf(`{"state_token": "%s", "otp": "%s"}`, state, otp.Generate()))
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("POST", "/validate-otp", body)
		r.Header.Set("Content-Type", "application/json")

		e.ServeHTTP(w, r)
		resp := w.Result()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		err := rmock.ExpectationsWereMet()
		assert.Equal(t, nil, err)
	})
}

// Helper function to create properly encrypted backup codes for testing
func createTestBackupCodesData(t *testing.T, codes []string) []byte {
	// Convert codes to BackupCode structs
	testBackupCodes := make([]backupcodes.BackupCode, len(codes))
	for i, code := range codes {
		testBackupCodes[i] = backupcodes.BackupCode{Code: code}
	}

	// Convert to JSON
	jsonData, err := json.Marshal(testBackupCodes)
	if err != nil {
		t.Fatal("Failed to marshal test backup codes:", err)
	}

	// Encrypt using actual encryption system
	encryption, err := backupcodes.NewBackupCodeEncryption()
	if err != nil {
		t.Fatal("Failed to create encryption for test:", err)
	}
	encryptedString, err := encryption.Encrypt(jsonData)
	if err != nil {
		t.Fatal("Failed to encrypt test backup codes:", err)
	}

	// Create metadata
	metadata := backupcodes.Metadata{
		EncryptedBackupCodes: encryptedString,
		GeneratedAt:          "2024-01-01T00:00:00Z",
		CodesRemaining:       len(codes),
	}

	// Convert to bytes
	mockBackupCodes, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal("Failed to marshal metadata:", err)
	}

	return mockBackupCodes
}

func TestAuthenticationController_BackupCodeAuthentication(t *testing.T) {
	seed := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	config.DefaultConfig()

	cTime := time.Now()
	timeMock := func() time.Time {
		return cTime
	}
	rt := time.Unix(timeMock().Add(time.Hour*24*7).Unix(), 0)

	t.Run("successful backup code authentication", func(t *testing.T) {
		db := mocks.NewServiceInterface(t)

		user := models.GetUserRow{
			ID:       1,
			Username: "testuser",
			Flags:    flags.UserTotpEnabled,
			TotpKey:  pgtype.Text{String: seed, Valid: true},
		}

		// Create realistic encrypted backup codes data containing "abcde-12345"
		testBackupCodes := []backupcodes.BackupCode{
			{Code: "abcde-12345"},
			{Code: "fghij-67890"},
			{Code: "klmno-13579"},
		}
		jsonData, _ := json.Marshal(testBackupCodes)

		// Use the actual encryption system to create proper test data
		encryption, err := backupcodes.NewBackupCodeEncryption()
		if err != nil {
			t.Fatal("Failed to create encryption for test:", err)
		}
		encryptedString, err := encryption.Encrypt(jsonData)
		if err != nil {
			t.Fatal("Failed to encrypt test backup codes:", err)
		}

		metadata := backupcodes.Metadata{
			EncryptedBackupCodes: encryptedString,
			GeneratedAt:          "2024-01-01T00:00:00Z",
			CodesRemaining:       3,
		}
		mockBackupCodes, _ := json.Marshal(metadata)

		mockBackupData := models.GetUserBackupCodesRow{
			BackupCodes:     mockBackupCodes,
			BackupCodesRead: pgtype.Bool{Bool: false, Valid: true},
		}

		db.On("GetUser", mock.Anything, models.GetUserParams{ID: int32(1)}).
			Return(user, nil).
			Times(2)
			// Called twice: once in VerifyFactor, once in checks/user
		db.On("GetUserBackupCodes", mock.Anything, int32(1)).
			Return(mockBackupData, nil).
			Times(3)
			// Called by GetBackupCodes, UpdateBackupCodes, ConsumeBackupCode
		db.On("UpdateUserBackupCodes", mock.Anything, mock.AnythingOfType("models.UpdateUserBackupCodesParams")).
			Return(nil).
			Once()
		db.On("GetAdminLevel", mock.Anything, int32(1)).Return(models.GetAdminLevelRow{}, nil).Once()
		db.On("ListUserRoles", mock.Anything, int32(1)).Return([]models.Role{}, nil).Once()

		rdb, rmock := redismock.NewClientMock()
		checks.InitUser(context.Background(), db)
		authController := NewAuthenticationController(db, rdb, timeMock)

		state, _ := authController.createStateToken(context.TODO(), 1)
		stateKey := fmt.Sprintf("user:mfa:state:%s", state)
		rmock.ExpectGet(stateKey).SetVal("1")
		rmock.ExpectDel(stateKey).SetVal(1)
		rmock.Regexp().ExpectSet("user:1:rt:", `.*`, rt.Sub(timeMock())).SetVal("1")

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.POST("/validate-otp", authController.VerifyFactor)

		// Test with a backup code that will be generated by the mock system
		body := bytes.NewBufferString(fmt.Sprintf(`{"state_token": "%s", "otp": "abcde-12345"}`, state))
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("POST", "/validate-otp", body)
		r.Header.Set("Content-Type", "application/json")

		e.ServeHTTP(w, r)
		resp := w.Result()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var loginResponse LoginResponse
		json.NewDecoder(resp.Body).Decode(&loginResponse)
		assert.NotEmpty(t, loginResponse.AccessToken)
		assert.NotEmpty(t, loginResponse.RefreshToken)

		err = rmock.ExpectationsWereMet()
		assert.NoError(t, err)
	})

	t.Run("backup code with different formats accepted", func(t *testing.T) {
		user := models.GetUserRow{
			ID:       1,
			Username: "testuser",
			Flags:    flags.UserTotpEnabled,
			TotpKey:  pgtype.Text{String: seed, Valid: true},
		}

		// Create proper encrypted mock data
		// The normalization removes spaces and hyphens, so "abcde-12345" normalizes to "abcde12345"
		mockBackupCodes := createTestBackupCodesData(t, []string{"abcde-12345", "fghij-67890", "klmno-13579"})
		mockBackupData := models.GetUserBackupCodesRow{
			BackupCodes:     mockBackupCodes,
			BackupCodesRead: pgtype.Bool{Bool: false, Valid: true},
		}

		// Test various input formats - all should normalize to match "abcde-12345" stored format
		// Note: validation limits OTP to 12 characters before normalization
		testCases := []struct {
			name  string
			input string
		}{
			{"standard format", "abcde-12345"}, // 11 chars - matches stored format exactly
			{"with spaces", "abcde 12345"},     // 11 chars - normalizes to "abcde-12345"
			{"no hyphen", "abcde12345"},        // 10 chars - hyphen will be added by normalization
			{"extra spaces", " abcde-12345"},   // 12 chars - leading space will be trimmed
			{"mixed spacing", "abc de 12345"},  // 12 chars - spaces removed, normalizes to "abcde-12345"
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Create fresh mock for each test case
				db := mocks.NewServiceInterface(t)
				db.On("GetUser", mock.Anything, models.GetUserParams{ID: int32(1)}).Return(user, nil).Times(2)
				db.On("GetUserBackupCodes", mock.Anything, int32(1)).Return(mockBackupData, nil).Times(3)
				db.On("UpdateUserBackupCodes", mock.Anything, mock.AnythingOfType("models.UpdateUserBackupCodesParams")).
					Return(nil).
					Once()
				db.On("GetAdminLevel", mock.Anything, int32(1)).Return(models.GetAdminLevelRow{}, nil).Once()
				db.On("ListUserRoles", mock.Anything, int32(1)).Return([]models.Role{}, nil).Once()

				rdb, rmock := redismock.NewClientMock()
				checks.InitUser(context.Background(), db)
				authController := NewAuthenticationController(db, rdb, timeMock)

				state, _ := authController.createStateToken(context.TODO(), 1)
				stateKey := fmt.Sprintf("user:mfa:state:%s", state)
				rmock.ExpectGet(stateKey).SetVal("1")
				rmock.ExpectDel(stateKey).SetVal(1)
				rmock.Regexp().ExpectSet("user:1:rt:", `.*`, rt.Sub(timeMock())).SetVal("1")

				e := echo.New()
				e.Validator = helper.NewValidator()
				e.POST("/validate-otp", authController.VerifyFactor)

				body := bytes.NewBufferString(fmt.Sprintf(`{"state_token": "%s", "otp": "%s"}`, state, tc.input))
				w := httptest.NewRecorder()
				r, _ := http.NewRequest("POST", "/validate-otp", body)
				r.Header.Set("Content-Type", "application/json")

				e.ServeHTTP(w, r)
				resp := w.Result()

				assert.Equal(t, http.StatusOK, resp.StatusCode)
				err := rmock.ExpectationsWereMet()
				assert.NoError(t, err)
			})
		}
	})

	t.Run("invalid backup code rejected", func(t *testing.T) {
		db := mocks.NewServiceInterface(t)

		user := models.GetUserRow{
			ID:       1,
			Username: "testuser",
			Flags:    flags.UserTotpEnabled,
			TotpKey:  pgtype.Text{String: seed, Valid: true},
		}

		// Create proper encrypted mock data - different codes so "wrong-code1" won't match
		mockBackupCodes := createTestBackupCodesData(t, []string{"valid-12345", "other-67890", "third-13579"})
		mockBackupData := models.GetUserBackupCodesRow{
			BackupCodes:     mockBackupCodes,
			BackupCodesRead: pgtype.Bool{Bool: false, Valid: true},
		}

		db.On("GetUser", mock.Anything, models.GetUserParams{ID: int32(1)}).Return(user, nil).Once()
		db.On("GetUserBackupCodes", mock.Anything, int32(1)).Return(mockBackupData, nil).Once()

		rdb, rmock := redismock.NewClientMock()
		checks.InitUser(context.Background(), db)
		authController := NewAuthenticationController(db, rdb, timeMock)

		state, _ := authController.createStateToken(context.TODO(), 1)
		stateKey := fmt.Sprintf("user:mfa:state:%s", state)
		rmock.ExpectGet(stateKey).SetVal("1")
		// Note: Redis state is NOT deleted on failed authentication

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.POST("/validate-otp", authController.VerifyFactor)

		// Test with invalid backup code
		body := bytes.NewBufferString(fmt.Sprintf(`{"state_token": "%s", "otp": "wrong-code1"}`, state))
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("POST", "/validate-otp", body)
		r.Header.Set("Content-Type", "application/json")

		e.ServeHTTP(w, r)
		resp := w.Result()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		err := rmock.ExpectationsWereMet()
		assert.NoError(t, err)
	})

	t.Run("no backup codes available", func(t *testing.T) {
		db := mocks.NewServiceInterface(t)

		user := models.GetUserRow{
			ID:       1,
			Username: "testuser",
			Flags:    flags.UserTotpEnabled,
			TotpKey:  pgtype.Text{String: seed, Valid: true},
		}

		// Mock empty backup codes
		mockBackupData := models.GetUserBackupCodesRow{
			BackupCodes:     []byte{},
			BackupCodesRead: pgtype.Bool{Bool: false, Valid: true},
		}

		db.On("GetUser", mock.Anything, models.GetUserParams{ID: int32(1)}).Return(user, nil).Once()
		db.On("GetUserBackupCodes", mock.Anything, int32(1)).Return(mockBackupData, nil).Once()

		rdb, rmock := redismock.NewClientMock()
		checks.InitUser(context.Background(), db)
		authController := NewAuthenticationController(db, rdb, timeMock)

		state, _ := authController.createStateToken(context.TODO(), 1)
		stateKey := fmt.Sprintf("user:mfa:state:%s", state)
		rmock.ExpectGet(stateKey).SetVal("1")
		// Note: Redis state is NOT deleted on failed authentication

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.POST("/validate-otp", authController.VerifyFactor)

		body := bytes.NewBufferString(fmt.Sprintf(`{"state_token": "%s", "otp": "abcde-12345"}`, state))
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("POST", "/validate-otp", body)
		r.Header.Set("Content-Type", "application/json")

		e.ServeHTTP(w, r)
		resp := w.Result()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		err := rmock.ExpectationsWereMet()
		assert.NoError(t, err)
	})

	t.Run("backup code case sensitivity", func(t *testing.T) {
		user := models.GetUserRow{
			ID:       1,
			Username: "testuser",
			Flags:    flags.UserTotpEnabled,
			TotpKey:  pgtype.Text{String: seed, Valid: true},
		}

		// Create proper encrypted mock data for case sensitivity tests
		mockBackupCodes := createTestBackupCodesData(t, []string{"abcde-12345", "fghij-67890", "klmno-13579"})
		mockBackupData := models.GetUserBackupCodesRow{
			BackupCodes:     mockBackupCodes,
			BackupCodesRead: pgtype.Bool{Bool: false, Valid: true},
		}

		// Test that case matters for backup codes
		testCases := []struct {
			name           string
			input          string
			expectedStatus int
		}{
			{"lowercase matches", "abcde-12345", http.StatusOK},
			{"uppercase different", "ABCDE-12345", http.StatusUnauthorized},
			{"mixed case different", "AbCdE-12345", http.StatusUnauthorized},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Create fresh mock for each test case
				db := mocks.NewServiceInterface(t)

				if tc.expectedStatus == http.StatusOK {
					db.On("GetUser", mock.Anything, models.GetUserParams{ID: int32(1)}).Return(user, nil).Times(2)
					db.On("GetUserBackupCodes", mock.Anything, int32(1)).Return(mockBackupData, nil).Times(3)
					db.On("UpdateUserBackupCodes", mock.Anything, mock.AnythingOfType("models.UpdateUserBackupCodesParams")).
						Return(nil).
						Once()
					db.On("GetAdminLevel", mock.Anything, int32(1)).Return(models.GetAdminLevelRow{}, nil).Once()
					db.On("ListUserRoles", mock.Anything, int32(1)).Return([]models.Role{}, nil).Once()
				} else {
					db.On("GetUser", mock.Anything, models.GetUserParams{ID: int32(1)}).Return(user, nil).Once()
					db.On("GetUserBackupCodes", mock.Anything, int32(1)).Return(mockBackupData, nil).Once()
				}

				rdb, rmock := redismock.NewClientMock()
				checks.InitUser(context.Background(), db)
				authController := NewAuthenticationController(db, rdb, timeMock)

				state, _ := authController.createStateToken(context.TODO(), 1)
				stateKey := fmt.Sprintf("user:mfa:state:%s", state)
				rmock.ExpectGet(stateKey).SetVal("1")

				if tc.expectedStatus == http.StatusOK {
					rmock.ExpectDel(stateKey).SetVal(1)
					rmock.Regexp().ExpectSet("user:1:rt:", `.*`, rt.Sub(timeMock())).SetVal("1")
				}
				// Note: Redis state is NOT deleted on failed authentication

				e := echo.New()
				e.Validator = helper.NewValidator()
				e.POST("/validate-otp", authController.VerifyFactor)

				body := bytes.NewBufferString(fmt.Sprintf(`{"state_token": "%s", "otp": "%s"}`, state, tc.input))
				w := httptest.NewRecorder()
				r, _ := http.NewRequest("POST", "/validate-otp", body)
				r.Header.Set("Content-Type", "application/json")

				e.ServeHTTP(w, r)
				resp := w.Result()

				assert.Equal(t, tc.expectedStatus, resp.StatusCode)
				err := rmock.ExpectationsWereMet()
				assert.NoError(t, err)
			})
		}
	})

	t.Run("database error retrieving backup codes", func(t *testing.T) {
		db := mocks.NewServiceInterface(t)

		user := models.GetUserRow{
			ID:       1,
			Username: "testuser",
			Flags:    flags.UserTotpEnabled,
			TotpKey:  pgtype.Text{String: seed, Valid: true},
		}

		db.On("GetUser", mock.Anything, models.GetUserParams{ID: int32(1)}).Return(user, nil).Once()
		db.On("GetUserBackupCodes", mock.Anything, int32(1)).
			Return(models.GetUserBackupCodesRow{}, errors.New("database error")).
			Once()

		rdb, rmock := redismock.NewClientMock()
		checks.InitUser(context.Background(), db)
		authController := NewAuthenticationController(db, rdb, timeMock)

		state, _ := authController.createStateToken(context.TODO(), 1)
		stateKey := fmt.Sprintf("user:mfa:state:%s", state)
		rmock.ExpectGet(stateKey).SetVal("1")
		// Note: Redis state is NOT deleted on database error (failed authentication)

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.POST("/validate-otp", authController.VerifyFactor)

		body := bytes.NewBufferString(fmt.Sprintf(`{"state_token": "%s", "otp": "abcde-12345"}`, state))
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("POST", "/validate-otp", body)
		r.Header.Set("Content-Type", "application/json")

		e.ServeHTTP(w, r)
		resp := w.Result()

		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
		err := rmock.ExpectationsWereMet()
		assert.NoError(t, err)
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

		// The JWT middleware returns a simple JSON object, not our structured error format
		var jwtError struct {
			Message string `json:"message"`
		}
		dec := json.NewDecoder(resp.Body)
		if err := dec.Decode(&jwtError); err != nil {
			t.Error("error decoding", err)
		}
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Contains(t, jwtError.Message, "missing or malformed jwt")
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
		db.On("GetUser", mock.Anything, models.GetUserParams{ID: int32(1)}).
			Return(models.GetUserRow{
				ID:       1,
				Username: "Admin",
			}, nil).Times(2)
		db.On("GetAdminLevel", mock.Anything, int32(1)).
			Return(models.GetAdminLevelRow{}, nil).Once()
		db.On("ListUserRoles", mock.Anything, int32(1)).
			Return([]models.Role{}, nil).Once()

		rdb, rmock := redismock.NewClientMock()
		rt := time.Unix(tokens.RtExpires.Unix(), 0)
		key := fmt.Sprintf("user:%d:rt:%s", claims.UserID, tokens.RefreshUUID)
		rmock.ExpectSet(key, strconv.Itoa(int(claims.UserID)), rt.Sub(n)).SetVal("1")
		rmock.ExpectDel(key).SetVal(1)
		rmock.Regexp().ExpectSet("user:1:rt:", `.*`, rt.Sub(n)).SetVal("1")

		checks.InitUser(context.Background(), db)
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

		cErr := new(apierrors.ErrorResponse)
		dec := json.NewDecoder(resp.Body)
		assert.NoError(t, dec.Decode(&cErr), "error decoding")
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		assert.Equal(t, "Refresh token expired", cErr.Error.Message)
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

		cErr := new(apierrors.ErrorResponse)
		dec := json.NewDecoder(resp.Body)
		assert.NoError(t, dec.Decode(&cErr), "error decoding")
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		assert.Equal(t, "Invalid or missing refresh token", cErr.Error.Message)
	})
}

func TestAuthenticationController_RequestPasswordReset(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    string
		expectedStatus int
		expectedMsg    string
		setupMock      func(*mocks.Querier)
	}{
		{
			name:           "valid email request",
			requestBody:    `{"email": "test@example.com"}`,
			expectedStatus: http.StatusOK,
			expectedMsg:    "If the email address exists in our system, you will receive a password reset link shortly.",
			setupMock: func(db *mocks.Querier) {
				// Mock user found by email
				db.On("GetUser", mock.Anything, models.GetUserParams{Email: "test@example.com"}).
					Return(models.GetUserRow{
						ID:       1,
						Username: "testuser",
					}, nil)
				// Mock checking for existing tokens
				db.On("GetActivePasswordResetTokensByUserID", mock.Anything, mock.AnythingOfType("pgtype.Int4"), mock.AnythingOfType("int32")).
					Return([]models.PasswordResetToken{}, nil)
				// Mock token creation
				db.On("CreatePasswordResetToken", mock.Anything, mock.AnythingOfType("models.CreatePasswordResetTokenParams")).
					Return(models.PasswordResetToken{
						Token: "test-token-123",
					}, nil)
			},
		},
		{
			name:           "email not found - still returns success",
			requestBody:    `{"email": "nonexistent@example.com"}`,
			expectedStatus: http.StatusOK,
			expectedMsg:    "If the email address exists in our system, you will receive a password reset link shortly.",
			setupMock: func(db *mocks.Querier) {
				// Mock user not found
				db.On("GetUser", mock.Anything, models.GetUserParams{Email: "nonexistent@example.com"}).
					Return(models.GetUserRow{}, pgx.ErrNoRows)
			},
		},
		{
			name:           "invalid email format",
			requestBody:    `{"email": "invalid-email"}`,
			expectedStatus: http.StatusBadRequest,
			expectedMsg:    "",
			setupMock:      func(_ *mocks.Querier) {},
		},
		{
			name:           "missing email field",
			requestBody:    `{}`,
			expectedStatus: http.StatusBadRequest,
			expectedMsg:    "",
			setupMock:      func(_ *mocks.Querier) {},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			db := mocks.NewQuerier(t)
			rdb, _ := redismock.NewClientMock()
			tt.setupMock(db)

			controller := NewAuthenticationController(db, rdb, func() time.Time {
				return time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
			})

			// Create request
			req := httptest.NewRequest(http.MethodPost, "/auth/password-reset", strings.NewReader(tt.requestBody))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			e := echo.New()
			e.Validator = helper.NewValidator()
			c := e.NewContext(req, rec)

			// Execute
			err := controller.RequestPasswordReset(c)

			// Assert
			switch tt.expectedStatus {
			case http.StatusOK:
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedStatus, rec.Code)

				var response passwordResetResponse
				err = json.Unmarshal(rec.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedMsg, response.Message)
			default:
				// For validation errors, the controller returns JSON with error details
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedStatus, rec.Code)
			}

			db.AssertExpectations(t)
		})
	}
}

func TestAuthenticationController_ResetPassword(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    string
		expectedStatus int
		expectedMsg    string
		setupMock      func(*mocks.Querier)
	}{
		{
			name:           "valid password reset",
			requestBody:    `{"token": "valid-token-123", "new_password": "NewSecurePass123!", "confirm_password": "NewSecurePass123!"}`,
			expectedStatus: http.StatusOK,
			expectedMsg:    "Your password has been successfully reset. You can now log in with your new password.",
			setupMock: func(db *mocks.Querier) {
				// Mock token validation - return valid token
				db.On("ValidatePasswordResetToken", mock.Anything, "valid-token-123", mock.AnythingOfType("int32")).
					Return(models.PasswordResetToken{
						UserID: pgtype.Int4{Int32: 1, Valid: true},
						Token:  "valid-token-123",
					}, nil)

				// Mock user lookup
				db.On("GetUser", mock.Anything, models.GetUserParams{ID: int32(1)}).Return(models.GetUserRow{
					ID:       1,
					Username: "testuser",
					Password: "oldhashedpass",
				}, nil)

				// Mock password update
				db.On("UpdateUserPassword", mock.Anything, mock.AnythingOfType("models.UpdateUserPasswordParams")).
					Return(nil)

				// Mock token marking as used
				db.On("MarkPasswordResetTokenAsUsed", mock.Anything, mock.AnythingOfType("models.MarkPasswordResetTokenAsUsedParams")).
					Return(nil)

				// Mock invalidating other tokens
				db.On("InvalidateUserPasswordResetTokens", mock.Anything, mock.AnythingOfType("pgtype.Int4"), mock.AnythingOfType("int32")).
					Return(nil)
			},
		},
		{
			name:           "invalid token",
			requestBody:    `{"token": "invalid-token", "new_password": "NewSecurePass123!", "confirm_password": "NewSecurePass123!"}`,
			expectedStatus: http.StatusUnauthorized,
			expectedMsg:    "Invalid or expired password reset token",
			setupMock: func(db *mocks.Querier) {
				// Mock token validation failure
				db.On("ValidatePasswordResetToken", mock.Anything, "invalid-token", mock.AnythingOfType("int32")).
					Return(models.PasswordResetToken{}, fmt.Errorf("token not found"))
			},
		},
		{
			name:           "password mismatch",
			requestBody:    `{"token": "valid-token", "new_password": "NewSecurePass123!", "confirm_password": "DifferentPassword!"}`,
			expectedStatus: http.StatusBadRequest,
			expectedMsg:    "",
			setupMock:      func(_ *mocks.Querier) {},
		},
		{
			name:           "missing token",
			requestBody:    `{"new_password": "NewSecurePass123!", "confirm_password": "NewSecurePass123!"}`,
			expectedStatus: http.StatusBadRequest,
			expectedMsg:    "",
			setupMock:      func(_ *mocks.Querier) {},
		},
		{
			name:           "weak password",
			requestBody:    `{"token": "valid-token", "new_password": "weak", "confirm_password": "weak"}`,
			expectedStatus: http.StatusBadRequest,
			expectedMsg:    "",
			setupMock:      func(_ *mocks.Querier) {},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			db := mocks.NewQuerier(t)
			rdb, _ := redismock.NewClientMock()
			tt.setupMock(db)

			controller := NewAuthenticationController(db, rdb, func() time.Time {
				return time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
			})

			// Create request
			req := httptest.NewRequest(http.MethodPost, "/auth/reset-password", strings.NewReader(tt.requestBody))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			e := echo.New()
			e.Validator = helper.NewValidator()
			c := e.NewContext(req, rec)

			// Execute
			err := controller.ResetPassword(c)

			// Assert
			switch tt.expectedStatus {
			case http.StatusOK:
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedStatus, rec.Code)

				var response resetPasswordResponse
				err = json.Unmarshal(rec.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedMsg, response.Message)
			case http.StatusUnauthorized:
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedStatus, rec.Code)

				var response apierrors.ErrorResponse
				err = json.Unmarshal(rec.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedMsg, response.Error.Message)
			default:
				// For validation errors, the controller returns JSON with error details
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedStatus, rec.Code)
			}

			db.AssertExpectations(t)
		})
	}
}
