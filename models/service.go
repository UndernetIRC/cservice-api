// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

// This file needs to be manually updated with the new models based on the file querier.go

// Package models contains the database models
package models

import (
	"context"
	"net/netip"

	"github.com/jackc/pgx/v5/pgtype"
)

// Service is a wrapper around the database queries
type Service struct {
	db *Queries
}

// NewService creates a new Service
func NewService(db *Queries) *Service {
	return &Service{db: db}
}

// CheckEmailExists checks if an email exists
func (s *Service) CheckEmailExists(ctx context.Context, uemail string) ([]pgtype.Text, error) {
	return s.db.CheckEmailExists(ctx, uemail)
}

// CheckUsernameExists checks if a username exists
func (s *Service) CheckUsernameExists(ctx context.Context, username string) ([]string, error) {
	return s.db.CheckUsernameExists(ctx, username)
}

// CreatePendingUser creates a new pending user
func (s *Service) CreatePendingUser(ctx context.Context, arg CreatePendingUserParams) (pgtype.Text, error) {
	return s.db.CreatePendingUser(ctx, arg)
}

// CreateUser creates a new user
func (s *Service) CreateUser(ctx context.Context, arg CreateUserParams) (User, error) {
	return s.db.CreateUser(ctx, arg)
}

// DeletePendingUserByCookie deletes a pending user by cookie
func (s *Service) DeletePendingUserByCookie(ctx context.Context, cookie pgtype.Text) error {
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
func (s *Service) GetUserByEmail(ctx context.Context, email string) (User, error) {
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
func (s *Service) GetWhiteListByIP(ctx context.Context, ip netip.Addr) (Whitelist, error) {
	return s.db.GetWhiteListByIP(ctx, ip)
}

// ListPendingUsers lists all pending users
func (s *Service) ListPendingUsers(ctx context.Context) ([]Pendinguser, error) {
	return s.db.ListPendingUsers(ctx)
}

func (s *Service) CreateRole(ctx context.Context, arg CreateRoleParams) (Role, error) {
	return s.db.CreateRole(ctx, arg)
}

func (s *Service) DeleteRole(ctx context.Context, id int32) error {
	return s.db.DeleteRole(ctx, id)
}

func (s *Service) GetRoleByID(ctx context.Context, id int32) (Role, error) {
	return s.db.GetRoleByID(ctx, id)
}

func (s *Service) GetRoleByName(ctx context.Context, name string) (Role, error) {
	return s.db.GetRoleByName(ctx, name)
}

func (s *Service) ListRoles(ctx context.Context) ([]Role, error) {
	return s.db.ListRoles(ctx)
}

func (s *Service) ListUserRoles(ctx context.Context, userID int32) ([]Role, error) {
	return s.db.ListUserRoles(ctx, userID)
}

func (s *Service) UpdateRole(ctx context.Context, arg UpdateRoleParams) error {
	return s.db.UpdateRole(ctx, arg)
}

func (s *Service) GetUsersByUsernames(ctx context.Context, usernames []string) ([]GetUsersByUsernamesRow, error) {
	return s.db.GetUsersByUsernames(ctx, usernames)
}

func (s *Service) GetAdminLevel(ctx context.Context, userID int32) (GetAdminLevelRow, error) {
	return s.db.GetAdminLevel(ctx, userID)
}

func (s *Service) GetUser(ctx context.Context, arg GetUserParams) (GetUserRow, error) {
	return s.db.GetUser(ctx, arg)
}

func (s *Service) AddUserRole(ctx context.Context, userID int32, roleID int32) error {
	return s.db.AddUserRole(ctx, userID, roleID)
}

func (s *Service) AddUsersToRole(ctx context.Context, arg []AddUsersToRoleParams) (int64, error) {
	return s.db.AddUsersToRole(ctx, arg)
}

func (s *Service) RemoveUserRole(ctx context.Context, userID int32, roleID int32) error {
	return s.db.RemoveUserRole(ctx, userID, roleID)
}

func (s *Service) RemoveUsersFromRole(ctx context.Context, userIDs []int32, roleID int32) error {
	return s.db.RemoveUsersFromRole(ctx, userIDs, roleID)
}
