// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package checks

import (
	"context"
	"errors"
	"fmt"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/undernetirc/cservice-api/db/mocks"

	"testing"
)

func TestUserService(t *testing.T) {
	ctx := context.Background()
	email := "test@example.com"
	username := "test"

	testCases := []struct {
		dbUsername string
		username   string
		dbEmail    string
		email      string
		errs       []error
	}{
		// Should throw errors
		{dbUsername: username, username: username, dbEmail: email, email: email, errs: []error{ErrUsernameExists, ErrEmailExists}},
		{dbUsername: username, username: username, dbEmail: "", email: email, errs: []error{ErrUsernameExists}},
		{dbUsername: "", username: username, dbEmail: email, email: email, errs: []error{ErrEmailExists}},
		// Should return nil
		{dbUsername: "", username: username, dbEmail: "", email: email, errs: nil},
	}

	t.Run("should return nil if user is not found", func(t *testing.T) {
		items := []string{}
		db := mocks.NewQuerier(t)
		db.On("CheckUsernameExists", mock.Anything, username).
			Return(items, nil).Once()
		InitUser(ctx, db)
		err := User.IsUsernameRegistered(username)
		assert.Equal(t, nil, err)
	})

	t.Run("should return ErrUsernameExists if a user is found", func(t *testing.T) {
		items := []string{}
		items = append(items, username)
		db := mocks.NewQuerier(t)
		db.On("CheckUsernameExists", mock.Anything, username).
			Return(items, nil).Once()
		InitUser(ctx, db)
		err := User.IsUsernameRegistered(username)
		assert.True(t, errors.Is(err, ErrUsernameExists))
	})

	t.Run("should return nil if email is not found", func(t *testing.T) {
		items := []*string{}
		db := mocks.NewQuerier(t)
		db.On("CheckEmailExists", mock.Anything, email).
			Return(items, nil).Once()
		InitUser(ctx, db)
		err := User.IsEmailRegistered(email)
		assert.Equal(t, nil, err)
	})

	t.Run("should return ErrEmailExists if an email is found", func(t *testing.T) {
		items := []*string{}
		items = append(items, &email)
		db := mocks.NewQuerier(t)
		db.On("CheckEmailExists", mock.Anything, email).
			Return(items, nil).Once()
		InitUser(ctx, db)
		err := User.IsEmailRegistered(email)
		assert.True(t, errors.Is(err, ErrEmailExists))
	})

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("User %s (%s) dbUser %s (%s)", tc.username, tc.email, tc.dbUsername, tc.dbEmail), func(t *testing.T) {
			userList := []string{}
			if tc.dbUsername != "" {
				userList = append(userList, tc.dbUsername)
			}
			emailList := []*string{}
			if tc.dbEmail != "" {
				emailList = append(emailList, &tc.dbEmail)
			}
			db := mocks.NewQuerier(t)
			db.On("CheckUsernameExists", mock.Anything, tc.username).
				Return(userList, nil).Once()
			db.On("CheckEmailExists", mock.Anything, tc.email).
				Return(emailList, nil).Once()
			InitUser(ctx, db)
			err := User.IsRegistered(tc.username, tc.email)
			if err != nil {
				for _, e := range tc.errs {
					assert.True(t, errors.Is(err, e))
				}
			}
		})
	}
}
