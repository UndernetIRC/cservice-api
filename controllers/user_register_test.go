package controllers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/undernetirc/cservice-api/db/mocks"
	"github.com/undernetirc/cservice-api/internal/checks"
	apierrors "github.com/undernetirc/cservice-api/internal/errors"
	"github.com/undernetirc/cservice-api/internal/helper"
	"github.com/undernetirc/cservice-api/models"
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
			e.POST("/register", controller.UserRegister)

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
				var errorResponse apierrors.ErrorResponse
				err := json.NewDecoder(resp.Body).Decode(&errorResponse)
				assert.Nil(t, err)
				assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
				for _, e := range tc.error {
					assert.Contains(t, errorResponse.Error.Message, e)
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

		// Add mock for CreatePendingUser in case tracing continues after validation failure
		db.On("CreatePendingUser", mock.Anything, mock.AnythingOfType("models.CreatePendingUserParams")).
			Return(pgtype.Text{}, fmt.Errorf("should not be called")).Maybe()

		checks.InitUser(context.Background(), db)
		controller := NewUserRegisterController(db, nil)

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.POST("/register", controller.UserRegister)

		body := bytes.NewBufferString(string(registrationJSON))
		w := httptest.NewRecorder()
		r, _ := http.NewRequest(http.MethodPost, "/register", body)
		r.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		e.ServeHTTP(w, r)
		resp := w.Result()

		var errorResponse apierrors.ErrorResponse
		err := json.NewDecoder(resp.Body).Decode(&errorResponse)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusConflict, resp.StatusCode)
		assert.Equal(t, checks.ErrUsernameExists.Error(), errorResponse.Error.Message)
	})

	t.Run("fail register because username exists", func(t *testing.T) {
		db := mocks.NewServiceInterface(t)
		db.On("CheckUsernameExists", mock.Anything, username).
			Return(userList, checks.ErrUsernameExists).Once()
		db.On("CheckEmailExists", mock.Anything, email).
			Return(emailList, checks.ErrEmailExists).Once()

		// Add mock for CreatePendingUser in case tracing continues after validation failure
		db.On("CreatePendingUser", mock.Anything, mock.AnythingOfType("models.CreatePendingUserParams")).
			Return(pgtype.Text{}, fmt.Errorf("should not be called")).Maybe()

		checks.InitUser(context.Background(), db)
		controller := NewUserRegisterController(db, nil)

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.POST("/register", controller.UserRegister)

		body := bytes.NewBufferString(string(registrationJSON))
		w := httptest.NewRecorder()
		r, _ := http.NewRequest(http.MethodPost, "/register", body)
		r.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		e.ServeHTTP(w, r)
		resp := w.Result()

		var errorResponse apierrors.ErrorResponse
		err := json.NewDecoder(resp.Body).Decode(&errorResponse)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusConflict, resp.StatusCode)
		assert.Contains(t, errorResponse.Error.Message, checks.ErrUsernameExists.Error())
		assert.Contains(t, errorResponse.Error.Message, checks.ErrEmailExists.Error())
	})
}

// MockTx is a mock implementation of pgx.Tx for testing
type MockTx struct {
	mock.Mock
}

func (m *MockTx) Begin(ctx context.Context) (pgx.Tx, error) {
	args := m.Called(ctx)
	return args.Get(0).(pgx.Tx), args.Error(1)
}

func (m *MockTx) Commit(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockTx) Rollback(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockTx) CopyFrom(ctx context.Context, tableName pgx.Identifier, columnNames []string, rowSrc pgx.CopyFromSource) (int64, error) {
	args := m.Called(ctx, tableName, columnNames, rowSrc)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockTx) SendBatch(ctx context.Context, b *pgx.Batch) pgx.BatchResults {
	args := m.Called(ctx, b)
	return args.Get(0).(pgx.BatchResults)
}

func (m *MockTx) LargeObjects() pgx.LargeObjects {
	args := m.Called()
	return args.Get(0).(pgx.LargeObjects)
}

func (m *MockTx) Prepare(ctx context.Context, name, sql string) (*pgconn.StatementDescription, error) {
	args := m.Called(ctx, name, sql)
	return args.Get(0).(*pgconn.StatementDescription), args.Error(1)
}

func (m *MockTx) Exec(ctx context.Context, sql string, arguments ...interface{}) (commandTag pgconn.CommandTag, err error) {
	args := m.Called(ctx, sql, arguments)
	return args.Get(0).(pgconn.CommandTag), args.Error(1)
}

func (m *MockTx) Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
	mockArgs := m.Called(ctx, sql, args)
	return mockArgs.Get(0).(pgx.Rows), mockArgs.Error(1)
}

func (m *MockTx) QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row {
	mockArgs := m.Called(ctx, sql, args)
	return mockArgs.Get(0).(pgx.Row)
}

func (m *MockTx) Conn() *pgx.Conn {
	args := m.Called()
	return args.Get(0).(*pgx.Conn)
}

// MockPool is a mock implementation of PoolInterface for testing
type MockPool struct {
	mock.Mock
}

func (m *MockPool) Begin(ctx context.Context) (pgx.Tx, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(pgx.Tx), args.Error(1)
}

func (m *MockPool) Close() {
	m.Called()
}

func TestUserRegisterController_UserActivateAccount(t *testing.T) {
	validToken := "valid-token-123"
	expiredToken := "expired-token-456"
	nonExistentToken := "non-existent-token"

	// Create test pending user data
	validPendingUser := models.Pendinguser{
		Username: pgtype.Text{String: "testuser", Valid: true},
		Cookie:   pgtype.Text{String: validToken, Valid: true},
		Email:    pgtype.Text{String: "test@example.com", Valid: true},
		Expire:   pgtype.Int4{Int32: int32(time.Now().Add(time.Hour).Unix()), Valid: true}, // Valid for 1 hour
		Language: pgtype.Int4{Int32: 1, Valid: true},
		Password: "hashedpassword123",
	}

	expiredPendingUser := models.Pendinguser{
		Username: pgtype.Text{String: "expireduser", Valid: true},
		Cookie:   pgtype.Text{String: expiredToken, Valid: true},
		Email:    pgtype.Text{String: "expired@example.com", Valid: true},
		Expire:   pgtype.Int4{Int32: int32(time.Now().Add(-time.Hour).Unix()), Valid: true}, // Expired 1 hour ago
		Language: pgtype.Int4{Int32: 1, Valid: true},
		Password: "hashedpassword456",
	}

	createdUser := models.User{
		ID:       123,
		Username: "testuser",
		Email:    pgtype.Text{String: "test@example.com", Valid: true},
		Password: "hashedpassword123",
	}

	testCases := []struct {
		name           string
		requestBody    string
		setupMocks     func(*mocks.ServiceInterface, *MockPool, *MockTx)
		expectedStatus int
		expectedError  string
		checkResponse  func(*testing.T, *httptest.ResponseRecorder)
	}{
		{
			name:           "missing token in request",
			requestBody:    `{}`,
			setupMocks:     func(_ *mocks.ServiceInterface, _ *MockPool, _ *MockTx) {},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "token is a required field",
		},
		{
			name:           "empty token in request",
			requestBody:    `{"token": ""}`,
			setupMocks:     func(_ *mocks.ServiceInterface, _ *MockPool, _ *MockTx) {},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "token is a required field",
		},
		{
			name:           "invalid JSON request",
			requestBody:    `{"token": }`,
			setupMocks:     func(_ *mocks.ServiceInterface, _ *MockPool, _ *MockTx) {},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:        "pending user not found",
			requestBody: fmt.Sprintf(`{"token": "%s"}`, nonExistentToken),
			setupMocks: func(db *mocks.ServiceInterface, pool *MockPool, tx *MockTx) {
				db.On("GetPendingUserByCookie", mock.Anything, pgtype.Text{String: nonExistentToken, Valid: true}).
					Return(models.Pendinguser{}, errors.New("user not found")).Once()

				// Add mocks for transaction operations in case tracing continues after user not found
				if pool != nil {
					pool.On("Begin", mock.Anything).Return(tx, nil).Maybe()
					mockQtx := mocks.NewServiceInterface(t)
					db.On("WithTx", tx).Return(mockQtx).Maybe()
					mockQtx.On("CreateUser", mock.Anything, mock.AnythingOfType("models.CreateUserParams")).
						Return(models.User{}, fmt.Errorf("should not be called")).Maybe()
					mockQtx.On("DeletePendingUserByCookie", mock.Anything, mock.Anything).
						Return(fmt.Errorf("should not be called")).Maybe()
					tx.On("Rollback", mock.Anything).Return(nil).Maybe()
				}
			},
			expectedStatus: http.StatusNotFound,
			expectedError:  "User not found",
		},
		{
			name:        "expired pending user token",
			requestBody: fmt.Sprintf(`{"token": "%s"}`, expiredToken),
			setupMocks: func(db *mocks.ServiceInterface, pool *MockPool, tx *MockTx) {
				db.On("GetPendingUserByCookie", mock.Anything, pgtype.Text{String: expiredToken, Valid: true}).
					Return(expiredPendingUser, nil).Once()
				db.On("DeletePendingUserByCookie", mock.Anything, expiredPendingUser.Cookie).
					Return(nil).Once()

				// Add mocks for transaction operations in case tracing continues after token expiry
				if pool != nil {
					pool.On("Begin", mock.Anything).Return(tx, nil).Maybe()
					mockQtx := mocks.NewServiceInterface(t)
					db.On("WithTx", tx).Return(mockQtx).Maybe()
					mockQtx.On("CreateUser", mock.Anything, mock.AnythingOfType("models.CreateUserParams")).
						Return(models.User{}, fmt.Errorf("should not be called")).Maybe()
					mockQtx.On("DeletePendingUserByCookie", mock.Anything, mock.Anything).
						Return(fmt.Errorf("should not be called")).Maybe()
					tx.On("Rollback", mock.Anything).Return(nil).Maybe()
				}
			},
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "Activation token has expired",
		},
		{
			name:        "expired pending user token with deletion error",
			requestBody: fmt.Sprintf(`{"token": "%s"}`, expiredToken),
			setupMocks: func(db *mocks.ServiceInterface, pool *MockPool, tx *MockTx) {
				db.On("GetPendingUserByCookie", mock.Anything, pgtype.Text{String: expiredToken, Valid: true}).
					Return(expiredPendingUser, nil).Once()
				db.On("DeletePendingUserByCookie", mock.Anything, expiredPendingUser.Cookie).
					Return(errors.New("deletion failed")).Once()

				// Add mocks for transaction operations in case tracing continues after deletion error
				if pool != nil {
					pool.On("Begin", mock.Anything).Return(tx, nil).Maybe()
					mockQtx := mocks.NewServiceInterface(t)
					db.On("WithTx", tx).Return(mockQtx).Maybe()
					mockQtx.On("CreateUser", mock.Anything, mock.AnythingOfType("models.CreateUserParams")).
						Return(models.User{}, fmt.Errorf("should not be called")).Maybe()
					mockQtx.On("DeletePendingUserByCookie", mock.Anything, mock.Anything).
						Return(fmt.Errorf("should not be called")).Maybe()
					tx.On("Rollback", mock.Anything).Return(nil).Maybe()
				}
			},
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "Activation token has expired",
		},
		{
			name:        "database transaction begin failure",
			requestBody: fmt.Sprintf(`{"token": "%s"}`, validToken),
			setupMocks: func(db *mocks.ServiceInterface, pool *MockPool, _ *MockTx) {
				db.On("GetPendingUserByCookie", mock.Anything, pgtype.Text{String: validToken, Valid: true}).
					Return(validPendingUser, nil).Once()
				pool.On("Begin", mock.Anything).
					Return(nil, errors.New("failed to start transaction")).Once()
			},
			expectedStatus: http.StatusInternalServerError,
			expectedError:  "An error occurred while processing your request",
		},
		{
			name:        "create user failure",
			requestBody: fmt.Sprintf(`{"token": "%s"}`, validToken),
			setupMocks: func(db *mocks.ServiceInterface, pool *MockPool, tx *MockTx) {
				db.On("GetPendingUserByCookie", mock.Anything, pgtype.Text{String: validToken, Valid: true}).
					Return(validPendingUser, nil).Once()
				pool.On("Begin", mock.Anything).
					Return(tx, nil).Once()

				// Mock WithTx to return a new service with transaction
				mockQtx := mocks.NewServiceInterface(t)
				db.On("WithTx", tx).Return(mockQtx).Once()

				mockQtx.On("CreateUser", mock.Anything, mock.AnythingOfType("models.CreateUserParams")).
					Return(models.User{}, errors.New("failed to create user")).Once()

				tx.On("Rollback", mock.Anything).Return(nil).Once()
			},
			expectedStatus: http.StatusInternalServerError,
			expectedError:  "An error occurred while processing your request",
		},
		{
			name:        "delete pending user failure",
			requestBody: fmt.Sprintf(`{"token": "%s"}`, validToken),
			setupMocks: func(db *mocks.ServiceInterface, pool *MockPool, tx *MockTx) {
				db.On("GetPendingUserByCookie", mock.Anything, pgtype.Text{String: validToken, Valid: true}).
					Return(validPendingUser, nil).Once()
				pool.On("Begin", mock.Anything).
					Return(tx, nil).Once()

				// Mock WithTx to return a new service with transaction
				mockQtx := mocks.NewServiceInterface(t)
				db.On("WithTx", tx).Return(mockQtx).Once()

				mockQtx.On("CreateUser", mock.Anything, mock.AnythingOfType("models.CreateUserParams")).
					Return(createdUser, nil).Once()
				mockQtx.On("DeletePendingUserByCookie", mock.Anything, validPendingUser.Cookie).
					Return(errors.New("failed to delete pending user")).Once()

				tx.On("Rollback", mock.Anything).Return(nil).Once()
			},
			expectedStatus: http.StatusInternalServerError,
			expectedError:  "An error occurred while processing your request",
		},
		{
			name:        "transaction commit failure",
			requestBody: fmt.Sprintf(`{"token": "%s"}`, validToken),
			setupMocks: func(db *mocks.ServiceInterface, pool *MockPool, tx *MockTx) {
				db.On("GetPendingUserByCookie", mock.Anything, pgtype.Text{String: validToken, Valid: true}).
					Return(validPendingUser, nil).Once()
				pool.On("Begin", mock.Anything).
					Return(tx, nil).Once()

				// Mock WithTx to return a new service with transaction
				mockQtx := mocks.NewServiceInterface(t)
				db.On("WithTx", tx).Return(mockQtx).Once()

				mockQtx.On("CreateUser", mock.Anything, mock.AnythingOfType("models.CreateUserParams")).
					Return(createdUser, nil).Once()
				mockQtx.On("DeletePendingUserByCookie", mock.Anything, validPendingUser.Cookie).
					Return(nil).Once()

				tx.On("Commit", mock.Anything).
					Return(errors.New("failed to commit transaction")).Once()
				tx.On("Rollback", mock.Anything).Return(nil).Once()
			},
			expectedStatus: http.StatusInternalServerError,
			expectedError:  "An error occurred while processing your request",
		},
		{
			name:        "successful activation",
			requestBody: fmt.Sprintf(`{"token": "%s"}`, validToken),
			setupMocks: func(db *mocks.ServiceInterface, pool *MockPool, tx *MockTx) {
				db.On("GetPendingUserByCookie", mock.Anything, pgtype.Text{String: validToken, Valid: true}).
					Return(validPendingUser, nil).Once()
				pool.On("Begin", mock.Anything).
					Return(tx, nil).Once()

				// Mock WithTx to return a new service with transaction
				mockQtx := mocks.NewServiceInterface(t)
				db.On("WithTx", tx).Return(mockQtx).Once()

				mockQtx.On("CreateUser", mock.Anything, mock.AnythingOfType("models.CreateUserParams")).
					Return(createdUser, nil).Once()
				mockQtx.On("DeletePendingUserByCookie", mock.Anything, validPendingUser.Cookie).
					Return(nil).Once()

				tx.On("Commit", mock.Anything).Return(nil).Once()
				tx.On("Rollback", mock.Anything).Return(nil).Once()
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, rec *httptest.ResponseRecorder) {
				var response UserRegisterActivateResponse
				err := json.NewDecoder(rec.Body).Decode(&response)
				assert.NoError(t, err)
				assert.Equal(t, "testuser", response.Username)
				assert.Equal(t, "test@example.com", response.Email)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mocks
			db := mocks.NewServiceInterface(t)
			pool := new(MockPool)
			tx := new(MockTx)

			tc.setupMocks(db, pool, tx)

			// Create controller
			controller := NewUserRegisterController(db, pool)

			// Setup Echo
			e := echo.New()
			e.Validator = helper.NewValidator()
			e.POST("/activate", controller.UserActivateAccount)

			// Create request
			body := bytes.NewBufferString(tc.requestBody)
			w := httptest.NewRecorder()
			r, _ := http.NewRequest(http.MethodPost, "/activate", body)
			r.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

			// Execute request
			e.ServeHTTP(w, r)
			resp := w.Result()

			// Assert status code
			assert.Equal(t, tc.expectedStatus, resp.StatusCode)

			// Check error response if expected
			if tc.expectedError != "" {
				var errorResponse apierrors.ErrorResponse
				err := json.NewDecoder(resp.Body).Decode(&errorResponse)
				assert.NoError(t, err)
				assert.Contains(t, errorResponse.Error.Message, tc.expectedError)
			}

			// Run custom response checks
			if tc.checkResponse != nil {
				tc.checkResponse(t, w)
			}

			// Verify all mocks were called as expected
			db.AssertExpectations(t)
			pool.AssertExpectations(t)
			tx.AssertExpectations(t)
		})
	}
}

// TestUserActivateAccount_CreateUserParams tests that the CreateUserParams are constructed correctly
func TestUserActivateAccount_CreateUserParams(t *testing.T) {
	validToken := "test-token"
	testTime := time.Now().UTC()

	pendingUser := models.Pendinguser{
		Username: pgtype.Text{String: "testuser", Valid: true},
		Cookie:   pgtype.Text{String: validToken, Valid: true},
		Email:    pgtype.Text{String: "test@example.com", Valid: true},
		Expire:   pgtype.Int4{Int32: int32(testTime.Add(time.Hour).Unix()), Valid: true},
		Language: pgtype.Int4{Int32: 2, Valid: true}, // Different language ID
		Password: "hashedpassword123",
	}

	createdUser := models.User{
		ID:       456,
		Username: "testuser",
		Email:    pgtype.Text{String: "test@example.com", Valid: true},
		Password: "hashedpassword123",
	}

	db := mocks.NewServiceInterface(t)
	pool := new(MockPool)
	tx := new(MockTx)

	db.On("GetPendingUserByCookie", mock.Anything, pgtype.Text{String: validToken, Valid: true}).
		Return(pendingUser, nil).Once()
	pool.On("Begin", mock.Anything).
		Return(tx, nil).Once()

	// Mock WithTx to return a new service with transaction
	mockQtx := mocks.NewServiceInterface(t)
	db.On("WithTx", tx).Return(mockQtx).Once()

	// Capture the CreateUserParams to verify they're constructed correctly
	var capturedParams models.CreateUserParams
	mockQtx.On("CreateUser", mock.Anything, mock.AnythingOfType("models.CreateUserParams")).
		Run(func(args mock.Arguments) {
			capturedParams = args.Get(1).(models.CreateUserParams)
		}).
		Return(createdUser, nil).Once()
	mockQtx.On("DeletePendingUserByCookie", mock.Anything, pendingUser.Cookie).
		Return(nil).Once()

	tx.On("Commit", mock.Anything).Return(nil).Once()
	tx.On("Rollback", mock.Anything).Return(nil).Once()

	controller := NewUserRegisterController(db, pool)

	e := echo.New()
	e.Validator = helper.NewValidator()
	e.POST("/activate", controller.UserActivateAccount)

	body := bytes.NewBufferString(fmt.Sprintf(`{"token": "%s"}`, validToken))
	w := httptest.NewRecorder()
	r, _ := http.NewRequest(http.MethodPost, "/activate", body)
	r.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	r.RemoteAddr = "192.168.1.100:12345" // Set a test IP

	e.ServeHTTP(w, r)

	// Verify the CreateUserParams were constructed correctly
	assert.Equal(t, "testuser", capturedParams.Username)
	assert.Equal(t, "hashedpassword123", string(capturedParams.Password))
	assert.Equal(t, pgtype.Text{String: "test@example.com", Valid: true}, capturedParams.Email)
	assert.Equal(t, pgtype.Int4{Int32: 2, Valid: true}, capturedParams.LanguageID)
	assert.Equal(t, pgtype.Int4{Int32: 1, Valid: true}, capturedParams.Maxlogins)
	assert.True(t, capturedParams.SignupTs.Valid)
	assert.True(t, capturedParams.SignupIp.Valid)

	// Verify response
	assert.Equal(t, http.StatusOK, w.Code)

	var response UserRegisterActivateResponse
	err := json.NewDecoder(w.Body).Decode(&response)
	assert.NoError(t, err)
	assert.Equal(t, "testuser", response.Username)
	assert.Equal(t, "test@example.com", response.Email)
}
