// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

// Package checks contains functions intended for Is, Has, etc. checks
package checks

import (
	"context"
	"errors"

	"github.com/undernetirc/cservice-api/models"
)

// UserService contains the context and the database service
type UserService struct {
	c context.Context
	s models.Querier
}

// ErrUsernameExists is returned when a username is already registered
var ErrUsernameExists = errors.New("username already exists")

// ErrEmailExists is returned when an email is already registered
var ErrEmailExists = errors.New("email already exists")

// User is the UserService instance
var User *UserService

// InitUser initializes the UserService
func InitUser(ctx context.Context, s models.Querier) {
	User = &UserService{
		c: ctx,
		s: s,
	}
}

// IsUsernameRegistered checks if a username is already registered
func (u *UserService) IsUsernameRegistered(username string) error {
	res, err := u.s.CheckUsernameExists(u.c, username)
	if err != nil {
		return err
	}
	if len(res) > 0 {
		return ErrUsernameExists
	}
	return nil
}

// IsEmailRegistered checks if an email is already registered
func (u *UserService) IsEmailRegistered(email string) error {
	res, err := u.s.CheckEmailExists(u.c, email)
	if err != nil {
		return err
	}
	if len(res) > 0 {
		return ErrEmailExists
	}
	return nil
}

// IsRegistered checks if a username and email are already registered
func (u *UserService) IsRegistered(username string, email string) error {
	err1 := u.IsUsernameRegistered(username)
	err2 := u.IsEmailRegistered(email)
	return errors.Join(err1, err2)
}
