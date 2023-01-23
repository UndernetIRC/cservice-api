// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

// This file needs to be manually updated with the new models based on the file querier.go

package models

import (
	"context"

	"github.com/jackc/pgtype"
)

type Service struct {
	db *Queries
}

func NewService(db *Queries) *Service {
	return &Service{db: db}
}

func (s *Service) CreatePendingUser(ctx context.Context, arg CreatePendingUserParams) (*string, error) {
	return s.db.CreatePendingUser(ctx, arg)
}

func (s *Service) CreateUser(ctx context.Context, arg CreateUserParams) (User, error) {
	return s.db.CreateUser(ctx, arg)
}

func (s *Service) DeletePendingUserByCookie(ctx context.Context, cookie *string) error {
	return s.db.DeletePendingUserByCookie(ctx, cookie)
}

func (s *Service) GetUserByID(ctx context.Context, id int32) (GetUserByIDRow, error) {
	return s.db.GetUserByID(ctx, id)
}

func (s *Service) GetUserByUsername(ctx context.Context, username string) (User, error) {
	return s.db.GetUserByUsername(ctx, username)
}

func (s *Service) GetUserByEmail(ctx context.Context, email *string) (User, error) {
	return s.db.GetUserByEmail(ctx, email)
}

func (s *Service) GetUserChannels(ctx context.Context, userID int32) ([]GetUserChannelsRow, error) {
	return s.db.GetUserChannels(ctx, userID)
}

func (s *Service) GetWhiteListByIP(ctx context.Context, ip pgtype.Inet) (Whitelist, error) {
	return s.db.GetWhiteListByIP(ctx, ip)
}

func (s *Service) ListPendingUsers(ctx context.Context) ([]Pendinguser, error) {
	return s.db.ListPendingUsers(ctx)
}
