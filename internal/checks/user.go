// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

// Package checks contains functions intended for Is, Has, etc. checks
package checks

import (
	"context"
	"errors"
	"time"

	"github.com/undernetirc/cservice-api/db/types/flags"

	"github.com/jackc/pgx/v5"

	"github.com/undernetirc/cservice-api/models"
)

// userService contains the context and the database service
type userService struct {
	c context.Context
	s models.Querier
}

// ErrUsernameExists is returned when a username is already registered
var ErrUsernameExists = errors.New("username already exists")

// ErrEmailExists is returned when an email is already registered
var ErrEmailExists = errors.New("email already exists")

// User is the UserService instance
var User *userService

// InitUser initializes the UserService
func InitUser(ctx context.Context, s models.Querier) {
	User = &userService{
		c: ctx,
		s: s,
	}
}

// IsUsernameRegistered checks if a username is already registered
func (u *userService) IsUsernameRegistered(username string) error {
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
func (u *userService) IsEmailRegistered(email string) error {
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
func (u *userService) IsRegistered(username string, email string) error {
	err1 := u.IsUsernameRegistered(username)
	err2 := u.IsEmailRegistered(email)
	return errors.Join(err1, err2)
}

// IsAdmin checks if a user is an admin and returns their admin level

func (u *userService) IsAdmin(userID int32) (int32, error) {
	user, err := u.s.GetUser(u.c, models.GetUserParams{
		ID: userID,
	})
	if err != nil {
		return 0, err
	}

	l, err := u.s.GetAdminLevel(u.c, user.ID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, nil
		}
		return 0, err
	}

	// If the user has been suspended, return 0
	if int64(l.SuspendExpires.Int32) > time.Now().Unix() {
		return 0, nil
	}

	// If the user is not an admin or is an alumni, and still is a member of *, they should not have admin level set
	if user.Flags.HasFlag(flags.UserNoAdmin) || user.Flags.HasFlag(flags.UserAlumni) {
		return 0, nil
	}

	return l.Access, nil
}
