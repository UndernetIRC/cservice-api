// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

// This file needs to be manually updated with the new models based on the file querier.go

// Package models contains the database models
package models

import (
	"context"

	"github.com/jackc/pgtype"
)

// Service is a wrapper around the database queries
type Service struct {
	db *Queries
}

// NewService creates a new Service
func NewService(db *Queries) *Service {
	return &Service{db: db}
}

// CreatePendingUser creates a new pending user
func (s *Service) CreatePendingUser(ctx context.Context, arg CreatePendingUserParams) (*string, error) {
	return s.db.CreatePendingUser(ctx, arg)
}

// CreateUser creates a new user
func (s *Service) CreateUser(ctx context.Context, arg CreateUserParams) (User, error) {
	return s.db.CreateUser(ctx, arg)
}

// DeletePendingUserByCookie deletes a pending user by cookie
func (s *Service) DeletePendingUserByCookie(ctx context.Context, cookie *string) error {
	return s.db.DeletePendingUserByCookie(ctx, cookie)
}

// GetUserByID gets a user by ID
func (s *Service) GetUserByID(ctx context.Context, id int32) (GetUserByIDRow, error) {
	return s.db.GetUserByID(ctx, id)
}

// GetUserByUsername gets a user by username
func (s *Service) GetUserByUsername(ctx context.Context, username string) (User, error) {
	return s.db.GetUserByUsername(ctx, username)
}

// GetUserByEmail gets a user by email
func (s *Service) GetUserByEmail(ctx context.Context, email *string) (User, error) {
	return s.db.GetUserByEmail(ctx, email)
}

// GetUserChannels gets a user's channels
func (s *Service) GetUserChannels(ctx context.Context, userID int32) ([]GetUserChannelsRow, error) {
	return s.db.GetUserChannels(ctx, userID)
}

// GetGlineByIP returns a gline entry by IP if it exists
func (s *Service) GetGlineByIP(ctx context.Context, ip string) (Gline, error) {
	return s.db.GetGlineByIP(ctx, ip)
}

// GetWhiteListByIP returns a whitelist entry by IP if it exists
func (s *Service) GetWhiteListByIP(ctx context.Context, ip pgtype.Inet) (Whitelist, error) {
	return s.db.GetWhiteListByIP(ctx, ip)
}

// ListPendingUsers lists all pending users
func (s *Service) ListPendingUsers(ctx context.Context) ([]Pendinguser, error) {
	return s.db.ListPendingUsers(ctx)
}
