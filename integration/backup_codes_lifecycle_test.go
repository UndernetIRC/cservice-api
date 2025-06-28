//go:build integration

// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2024 UnderNET

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/undernetirc/cservice-api/controllers"
	"github.com/undernetirc/cservice-api/db/types/password"
	"github.com/undernetirc/cservice-api/internal/auth/oath/totp"
	"github.com/undernetirc/cservice-api/internal/checks"
	"github.com/undernetirc/cservice-api/internal/config"
	"github.com/undernetirc/cservice-api/internal/helper"
	"github.com/undernetirc/cservice-api/models"
	"github.com/undernetirc/cservice-api/routes"

	"github.com/jackc/pgx/v5/pgtype"
)

// TestBackupCodeLifecycle tests the complete backup code lifecycle
func TestBackupCodeLifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration tests in short mode")
	}

	// Initialize configuration
	config.DefaultConfig()

	// Initialize checks
	ctx := context.Background()
	checks.InitUser(ctx, db)

	// Set up the service and controllers
	service := models.NewService(db)
	e := routes.NewEcho()
	routeService := routes.NewRouteService(e, service, dbPool, rdb)

	// Load routes
	err := routes.LoadRoutesWithOptions(routeService, false)
	require.NoError(t, err)

	// Create test user
	testUser := createTestUser(t, service)

	// Create JWT tokens for the test user
	userClaims := &helper.JwtClaims{
		UserID:   testUser.ID,
		Username: testUser.Username,
	}
	tokens, err := helper.GenerateToken(userClaims, time.Now())
	require.NoError(t, err)

	t.Run("Complete Backup Code Lifecycle", func(t *testing.T) {
		// Step 1: Enable 2FA (TOTP) - prerequisite for backup codes
		totpSecret := enableTOTPFor2FA(t, e, tokens.AccessToken, testUser.Username)

		// Step 2: Generate backup codes
		backupCodes := generateBackupCodes(t, e, tokens.AccessToken, totpSecret)
		assert.Len(t, backupCodes.BackupCodes, 10) // Should generate 10 backup codes

		// Step 3: Verify user endpoint shows backup code status
		userResponse := getCurrentUser(t, e, tokens.AccessToken)
		assert.True(t, userResponse.TotpEnabled)
		assert.True(t, userResponse.BackupCodesGenerated)
		assert.False(t, userResponse.BackupCodesRead)
		assert.Equal(t, 0, userResponse.BackupCodesRemaining) // No warning, so should be 0
		assert.False(t, userResponse.BackupCodesWarning)

		// Step 4: Retrieve backup codes (first time)
		retrievedCodes := getBackupCodes(t, e, tokens.AccessToken)
		assert.Len(t, retrievedCodes.BackupCodes, 10)
		assert.Equal(t, 10, retrievedCodes.CodesRemaining)

		// Step 5: Verify codes are marked as read
		userResponseAfterRead := getCurrentUser(t, e, tokens.AccessToken)
		assert.True(t, userResponseAfterRead.BackupCodesRead)

		// Step 6: Try to retrieve codes again (should fail - already read)
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/api/v1/user/backup-codes", nil)
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		e.ServeHTTP(w, req)
		assert.Equal(t, http.StatusForbidden, w.Code)

		// Step 7: Authenticate using a backup code
		firstBackupCode := retrievedCodes.BackupCodes[0]
		authenticateWithBackupCode(t, e, testUser.Username, firstBackupCode)

		// Step 8: Verify code count decreased
		userResponseAfterAuth := getCurrentUser(t, e, tokens.AccessToken)
		assert.True(t, userResponseAfterAuth.BackupCodesGenerated)
		// After using one code, we should have 9 remaining, which is > 3, so no warning
		assert.Equal(t, 0, userResponseAfterAuth.BackupCodesRemaining)
		assert.False(t, userResponseAfterAuth.BackupCodesWarning)

		// Step 9: Use more backup codes to trigger warning (use 7 more codes)
		for i := 1; i < 8; i++ {
			authenticateWithBackupCode(t, e, testUser.Username, retrievedCodes.BackupCodes[i])
		}

		// Step 10: Verify low backup code warning
		userResponseWithWarning := getCurrentUser(t, e, tokens.AccessToken)
		assert.True(t, userResponseWithWarning.BackupCodesGenerated)
		assert.Equal(t, 2, userResponseWithWarning.BackupCodesRemaining) // 2 codes remaining
		assert.True(t, userResponseWithWarning.BackupCodesWarning)       // Should show warning

		// Step 11: Regenerate backup codes
		newBackupCodes := regenerateBackupCodes(t, e, tokens.AccessToken, totpSecret)
		assert.Len(t, newBackupCodes.BackupCodes, 10)
		assert.Equal(t, 10, newBackupCodes.CodesRemaining)

		// Step 12: Verify codes are fresh and not read
		userResponseAfterRegen := getCurrentUser(t, e, tokens.AccessToken)
		assert.True(t, userResponseAfterRegen.BackupCodesGenerated)
		assert.False(t, userResponseAfterRegen.BackupCodesRead)         // Should be false after regeneration
		assert.Equal(t, 0, userResponseAfterRegen.BackupCodesRemaining) // No warning, so 0
		assert.False(t, userResponseAfterRegen.BackupCodesWarning)

		// Step 13: Verify old backup codes no longer work
		w = httptest.NewRecorder()
		loginReq := map[string]interface{}{
			"username": testUser.Username,
			"password": "testpassword123",
		}
		loginBody, _ := json.Marshal(loginReq)
		req = httptest.NewRequest("POST", "/api/v1/login", bytes.NewBuffer(loginBody))
		req.Header.Set("Content-Type", "application/json")
		e.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)

		var loginResponse map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &loginResponse)
		require.NoError(t, err)
		stateToken := loginResponse["state_token"].(string)

		// Try using an old backup code (should fail)
		w = httptest.NewRecorder()
		otpReq := map[string]interface{}{
			"otp":         retrievedCodes.BackupCodes[8], // Old backup code
			"state_token": stateToken,
		}
		otpBody, _ := json.Marshal(otpReq)
		req = httptest.NewRequest("POST", "/api/v1/authn/factor_verify", bytes.NewBuffer(otpBody))
		req.Header.Set("Content-Type", "application/json")
		e.ServeHTTP(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code) // Should fail with old code
	})

	// Clean up test user
	cleanupTestUser(t, service, testUser.ID)
}

// Helper functions for the test

func createTestUser(t *testing.T, service *models.Service) models.User {
	ctx := context.Background()

	// Create password
	pwd := password.Password("")
	err := pwd.Set("testpassword123")
	require.NoError(t, err)

	createParams := models.CreateUserParams{
		Username:         fmt.Sprintf("test_%d", time.Now().Unix()%100000),
		Email:            pgtype.Text{String: "backup_test@test.com", Valid: true},
		Password:         pwd,
		Flags:            0, // Start without 2FA
		LastUpdated:      int32(time.Now().Unix()),
		LastUpdatedBy:    pgtype.Text{String: "test", Valid: true},
		LanguageID:       pgtype.Int4{Int32: 1, Valid: true},
		QuestionID:       pgtype.Int2{Int16: 1, Valid: true},
		Verificationdata: pgtype.Text{String: "test_data", Valid: true},
		PostForms:        0,
		SignupTs:         pgtype.Int4{Int32: int32(time.Now().Unix()), Valid: true},
		SignupIp:         pgtype.Text{String: "127.0.0.1", Valid: true},
		Maxlogins:        pgtype.Int4{Int32: 1, Valid: true},
	}

	user, err := service.CreateUser(ctx, createParams)
	require.NoError(t, err)
	return user
}

func enableTOTPFor2FA(t *testing.T, e *echo.Echo, accessToken, username string) string {
	// Step 1: Enroll in 2FA
	w := httptest.NewRecorder()
	enrollReq := map[string]string{
		"current_password": "testpassword123",
	}
	enrollBody, _ := json.Marshal(enrollReq)
	req := httptest.NewRequest("POST", "/api/v1/user/2fa/enroll", bytes.NewBuffer(enrollBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	e.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var enrollResponse controllers.EnrollTOTPResponse
	err := json.Unmarshal(w.Body.Bytes(), &enrollResponse)
	require.NoError(t, err)
	totpSecret := enrollResponse.Secret

	// Step 2: Generate a TOTP code and activate 2FA
	totpInstance := totp.New(totpSecret, 6, 30, 0)
	totpCode := totpInstance.Generate()

	w = httptest.NewRecorder()
	activateReq := map[string]string{
		"otp_code": totpCode,
	}
	activateBody, _ := json.Marshal(activateReq)
	req = httptest.NewRequest("POST", "/api/v1/user/2fa/activate", bytes.NewBuffer(activateBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	e.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	return totpSecret
}

func generateBackupCodes(t *testing.T, e *echo.Echo, accessToken, totpSecret string) controllers.RegenerateBackupCodesResponse {
	// Generate TOTP code for verification
	totpInstance := totp.New(totpSecret, 6, 30, 0)
	totpCode := totpInstance.Generate()

	w := httptest.NewRecorder()
	regenReq := map[string]string{
		"totp_code": totpCode,
	}
	regenBody, _ := json.Marshal(regenReq)
	req := httptest.NewRequest("POST", "/api/v1/user/backup-codes", bytes.NewBuffer(regenBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	e.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var response controllers.RegenerateBackupCodesResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	return response
}

func getCurrentUser(t *testing.T, e *echo.Echo, accessToken string) controllers.UserResponse {
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/user", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	e.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var response controllers.UserResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	return response
}

func getBackupCodes(t *testing.T, e *echo.Echo, accessToken string) controllers.BackupCodesResponse {
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/user/backup-codes", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	e.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var response controllers.BackupCodesResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	return response
}

func authenticateWithBackupCode(t *testing.T, e *echo.Echo, username, backupCode string) {
	// Step 1: Login to get state token
	w := httptest.NewRecorder()
	loginReq := map[string]interface{}{
		"username": username,
		"password": "testpassword123",
	}
	loginBody, _ := json.Marshal(loginReq)
	req := httptest.NewRequest("POST", "/api/v1/login", bytes.NewBuffer(loginBody))
	req.Header.Set("Content-Type", "application/json")
	e.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var loginResponse map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &loginResponse)
	require.NoError(t, err)
	stateToken := loginResponse["state_token"].(string)

	// Step 2: Use backup code for 2FA
	w = httptest.NewRecorder()
	otpReq := map[string]interface{}{
		"otp":         backupCode,
		"state_token": stateToken,
	}
	otpBody, _ := json.Marshal(otpReq)
	req = httptest.NewRequest("POST", "/api/v1/authn/factor_verify", bytes.NewBuffer(otpBody))
	req.Header.Set("Content-Type", "application/json")
	e.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
}

func regenerateBackupCodes(t *testing.T, e *echo.Echo, accessToken, totpSecret string) controllers.RegenerateBackupCodesResponse {
	// Generate TOTP code for verification
	totpInstance := totp.New(totpSecret, 6, 30, 0)
	totpCode := totpInstance.Generate()

	w := httptest.NewRecorder()
	regenReq := map[string]string{
		"totp_code": totpCode,
	}
	regenBody, _ := json.Marshal(regenReq)
	req := httptest.NewRequest("POST", "/api/v1/user/backup-codes", bytes.NewBuffer(regenBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	e.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var response controllers.RegenerateBackupCodesResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	return response
}

func cleanupTestUser(t *testing.T, service *models.Service, userID int32) {
	ctx := context.Background()
	// Note: In a real application, you might want to implement a DeleteUser method
	// For now, we'll leave the test user in the database as it's a test environment
	_ = userID
	_ = service
	_ = ctx
}
