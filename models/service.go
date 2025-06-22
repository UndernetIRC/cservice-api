// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

// This file needs to be manually updated with the new models based on the file querier.go

// Package models contains the database models
package models

import (
	"context"
	"net/netip"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// ServiceInterface is an interface for the database model
type ServiceInterface interface {
	Querier
	WithTx(tx pgx.Tx) ServiceInterface
}

// Service is a wrapper around the database queries
type Service struct {
	db *Queries
}

// NewService creates a new Service
func NewService(db *Queries) *Service {
	return &Service{db: db}
}

// AddChannelMember adds a new member to a channel
func (s *Service) AddChannelMember(ctx context.Context, arg AddChannelMemberParams) (AddChannelMemberRow, error) {
	return s.db.AddChannelMember(ctx, arg)
}

// AddChannelOwner adds the manager as owner (access 500) for instant registration
func (s *Service) AddChannelOwner(ctx context.Context, channelID int32, userID int32) error {
	return s.db.AddChannelOwner(ctx, channelID, userID)
}

// AddUserRole adds a user role
func (s *Service) AddUserRole(ctx context.Context, userID int32, roleID int32) error {
	return s.db.AddUserRole(ctx, userID, roleID)
}

// AddUsersToRole adds users to a role
func (s *Service) AddUsersToRole(ctx context.Context, arg []AddUsersToRoleParams) (int64, error) {
	return s.db.AddUsersToRole(ctx, arg)
}

// CheckChannelExists checks if a channel exists
func (s *Service) CheckChannelExists(ctx context.Context, id int32) (CheckChannelExistsRow, error) {
	return s.db.CheckChannelExists(ctx, id)
}

// CheckChannelMemberExists checks if a user is already a member of a channel
func (s *Service) CheckChannelMemberExists(
	ctx context.Context,
	channelID int32,
	userID int32,
) (CheckChannelMemberExistsRow, error) {
	return s.db.CheckChannelMemberExists(ctx, channelID, userID)
}

// CheckChannelNameExists checks if a channel name already exists
func (s *Service) CheckChannelNameExists(ctx context.Context, lower string) (CheckChannelNameExistsRow, error) {
	return s.db.CheckChannelNameExists(ctx, lower)
}

// CheckChannelNoregStatus checks if a channel name is in NOREG
func (s *Service) CheckChannelNoregStatus(ctx context.Context, lower string) (CheckChannelNoregStatusRow, error) {
	return s.db.CheckChannelNoregStatus(ctx, lower)
}

// CheckEmailExists checks if an email exists
func (s *Service) CheckEmailExists(ctx context.Context, email string) ([]pgtype.Text, error) {
	return s.db.CheckEmailExists(ctx, email)
}

// CheckMultipleSupportersConcurrentSupports efficiently checks concurrent supports for multiple supporters at once
func (s *Service) CheckMultipleSupportersConcurrentSupports(
	ctx context.Context,
	column1 []string,
	column2 int32,
) ([]CheckMultipleSupportersConcurrentSupportsRow, error) {
	return s.db.CheckMultipleSupportersConcurrentSupports(ctx, column1, column2)
}

// CheckMultipleSupportersNoregStatus efficiently checks NOREG status for multiple supporters at once
func (s *Service) CheckMultipleSupportersNoregStatus(
	ctx context.Context,
	usernames []string,
) ([]CheckMultipleSupportersNoregStatusRow, error) {
	return s.db.CheckMultipleSupportersNoregStatus(ctx, usernames)
}

// CheckPendingChannelNameConflict checks if there's already a pending registration for this channel name
func (s *Service) CheckPendingChannelNameConflict(
	ctx context.Context,
	lower string,
) (CheckPendingChannelNameConflictRow, error) {
	return s.db.CheckPendingChannelNameConflict(ctx, lower)
}

// CheckSupporterConcurrentSupports checks how many channels a supporter is currently supporting
func (s *Service) CheckSupporterConcurrentSupports(ctx context.Context, userID int32) (int64, error) {
	return s.db.CheckSupporterConcurrentSupports(ctx, userID)
}

// CheckSupporterNoregStatus checks if a supporter has NOREG status
func (s *Service) CheckSupporterNoregStatus(ctx context.Context, lower string) (bool, error) {
	return s.db.CheckSupporterNoregStatus(ctx, lower)
}

// CheckUserNoregStatus checks if a user has NOREG status
func (s *Service) CheckUserNoregStatus(ctx context.Context, lower string) (bool, error) {
	return s.db.CheckUserNoregStatus(ctx, lower)
}

// CheckUsernameExists checks if a username exists
func (s *Service) CheckUsernameExists(ctx context.Context, username string) ([]string, error) {
	return s.db.CheckUsernameExists(ctx, username)
}

// CleanupExpiredNoreg removes expired NOREG entries
func (s *Service) CleanupExpiredNoreg(ctx context.Context) error {
	return s.db.CleanupExpiredNoreg(ctx)
}

// CleanupExpiredPasswordResetTokens cleans up expired password reset tokens
func (s *Service) CleanupExpiredPasswordResetTokens(ctx context.Context, expiresAt int32, lastUpdated int32) error {
	return s.db.CleanupExpiredPasswordResetTokens(ctx, expiresAt, lastUpdated)
}

// CountChannelOwners counts the number of owners in a channel
func (s *Service) CountChannelOwners(ctx context.Context, channelID int32) (int64, error) {
	return s.db.CountChannelOwners(ctx, channelID)
}

// CreateChannel creates a new channel entry
func (s *Service) CreateChannel(ctx context.Context, arg CreateChannelParams) (CreateChannelRow, error) {
	return s.db.CreateChannel(ctx, arg)
}

// CreateChannelForInstantRegistration creates a new channel entry for instant registration
func (s *Service) CreateChannelForInstantRegistration(
	ctx context.Context,
	name string,
) (CreateChannelForInstantRegistrationRow, error) {
	return s.db.CreateChannelForInstantRegistration(ctx, name)
}

// CreateChannelForRegistration creates a new channel entry for pending registration
func (s *Service) CreateChannelForRegistration(
	ctx context.Context,
	name string,
) (CreateChannelForRegistrationRow, error) {
	return s.db.CreateChannelForRegistration(ctx, name)
}

// CreateChannelSupporter adds a supporter to a pending channel registration
func (s *Service) CreateChannelSupporter(ctx context.Context, channelID int32, userID int32) error {
	return s.db.CreateChannelSupporter(ctx, channelID, userID)
}

// CreateInstantRegistration creates an instant registration
func (s *Service) CreateInstantRegistration(
	ctx context.Context,
	arg CreateInstantRegistrationParams,
) (CreateInstantRegistrationRow, error) {
	return s.db.CreateInstantRegistration(ctx, arg)
}

// CreatePasswordResetToken creates a new password reset token
func (s *Service) CreatePasswordResetToken(
	ctx context.Context,
	arg CreatePasswordResetTokenParams,
) (PasswordResetToken, error) {
	return s.db.CreatePasswordResetToken(ctx, arg)
}

// CreatePendingChannel creates a new pending channel registration
func (s *Service) CreatePendingChannel(
	ctx context.Context,
	arg CreatePendingChannelParams,
) (CreatePendingChannelRow, error) {
	return s.db.CreatePendingChannel(ctx, arg)
}

// CreatePendingUser creates a new pending user
func (s *Service) CreatePendingUser(ctx context.Context, arg CreatePendingUserParams) (pgtype.Text, error) {
	return s.db.CreatePendingUser(ctx, arg)
}

// CreateRole creates a new role
func (s *Service) CreateRole(ctx context.Context, arg CreateRoleParams) (Role, error) {
	return s.db.CreateRole(ctx, arg)
}

// CreateUser creates a new user
func (s *Service) CreateUser(ctx context.Context, arg CreateUserParams) (User, error) {
	return s.db.CreateUser(ctx, arg)
}

// DeleteChannelSupporters removes all supporters for a pending channel
func (s *Service) DeleteChannelSupporters(ctx context.Context, channelID int32) error {
	return s.db.DeleteChannelSupporters(ctx, channelID)
}

// DeleteExpiredPasswordResetTokens permanently deletes expired password reset tokens
func (s *Service) DeleteExpiredPasswordResetTokens(ctx context.Context, expiresAt int32) error {
	return s.db.DeleteExpiredPasswordResetTokens(ctx, expiresAt)
}

// DeletePendingChannel removes a pending channel registration
func (s *Service) DeletePendingChannel(ctx context.Context, channelID int32) error {
	return s.db.DeletePendingChannel(ctx, channelID)
}

// DeletePendingUserByCookie deletes a pending user by cookie
func (s *Service) DeletePendingUserByCookie(ctx context.Context, cookie pgtype.Text) error {
	return s.db.DeletePendingUserByCookie(ctx, cookie)
}

// DeleteRole deletes a role
func (s *Service) DeleteRole(ctx context.Context, id int32) error {
	return s.db.DeleteRole(ctx, id)
}

// DeleteSpecificChannelSupporter removes a specific supporter from a pending channel
func (s *Service) DeleteSpecificChannelSupporter(ctx context.Context, channelID int32, userID int32) error {
	return s.db.DeleteSpecificChannelSupporter(ctx, channelID, userID)
}

// GetActivePasswordResetTokensByUserID gets active password reset tokens for a user
func (s *Service) GetActivePasswordResetTokensByUserID(
	ctx context.Context,
	userID pgtype.Int4,
	expiresAt int32,
) ([]PasswordResetToken, error) {
	return s.db.GetActivePasswordResetTokensByUserID(ctx, userID, expiresAt)
}

// GetAdminLevel gets the admin level for a user
func (s *Service) GetAdminLevel(ctx context.Context, userID int32) (GetAdminLevelRow, error) {
	return s.db.GetAdminLevel(ctx, userID)
}

// GetChannelByID gets a channel by ID
func (s *Service) GetChannelByID(ctx context.Context, id int32) (GetChannelByIDRow, error) {
	return s.db.GetChannelByID(ctx, id)
}

// GetChannelByName gets a channel by name
func (s *Service) GetChannelByName(ctx context.Context, name string) (GetChannelByNameRow, error) {
	return s.db.GetChannelByName(ctx, name)
}

// GetChannelDetails gets detailed channel information
func (s *Service) GetChannelDetails(ctx context.Context, id int32) (GetChannelDetailsRow, error) {
	return s.db.GetChannelDetails(ctx, id)
}

// GetChannelMembersByAccessLevel gets channel members by access level
func (s *Service) GetChannelMembersByAccessLevel(
	ctx context.Context,
	channelID int32,
	access int32,
) ([]GetChannelMembersByAccessLevelRow, error) {
	return s.db.GetChannelMembersByAccessLevel(ctx, channelID, access)
}

// GetChannelUserAccess gets user access level for a channel
func (s *Service) GetChannelUserAccess(
	ctx context.Context,
	channelID int32,
	userID int32,
) (GetChannelUserAccessRow, error) {
	return s.db.GetChannelUserAccess(ctx, channelID, userID)
}

// GetGlineByIP returns a gline entry by IP if it exists
func (s *Service) GetGlineByIP(ctx context.Context, host string) (Gline, error) {
	return s.db.GetGlineByIP(ctx, host)
}

// GetLastChannelRegistration returns the timestamp of the user's last successful channel registration
func (s *Service) GetLastChannelRegistration(ctx context.Context, userID int32) (pgtype.Int4, error) {
	return s.db.GetLastChannelRegistration(ctx, userID)
}

// GetPasswordResetTokenByToken gets a password reset token by token string
func (s *Service) GetPasswordResetTokenByToken(ctx context.Context, token string) (PasswordResetToken, error) {
	return s.db.GetPasswordResetTokenByToken(ctx, token)
}

// GetPasswordResetTokenStats gets statistics about password reset tokens
func (s *Service) GetPasswordResetTokenStats(
	ctx context.Context,
	expiresAt int32,
) (GetPasswordResetTokenStatsRow, error) {
	return s.db.GetPasswordResetTokenStats(ctx, expiresAt)
}

// GetPendingUserByCookie gets a pending user by cookie
func (s *Service) GetPendingUserByCookie(ctx context.Context, cookie pgtype.Text) (Pendinguser, error) {
	return s.db.GetPendingUserByCookie(ctx, cookie)
}

// GetRoleByID gets a role by ID
func (s *Service) GetRoleByID(ctx context.Context, id int32) (Role, error) {
	return s.db.GetRoleByID(ctx, id)
}

// GetRoleByName gets a role by name
func (s *Service) GetRoleByName(ctx context.Context, name string) (Role, error) {
	return s.db.GetRoleByName(ctx, name)
}

// GetSupportersByUsernames gets all supporter information in one query
func (s *Service) GetSupportersByUsernames(
	ctx context.Context,
	column1 []string,
	column2 int32,
) ([]GetSupportersByUsernamesRow, error) {
	return s.db.GetSupportersByUsernames(ctx, column1, column2)
}

// GetUser gets a user
func (s *Service) GetUser(ctx context.Context, arg GetUserParams) (GetUserRow, error) {
	return s.db.GetUser(ctx, arg)
}

// GetUserChannelCount returns the count of channels owned by a user
func (s *Service) GetUserChannelCount(ctx context.Context, userID int32) (int64, error) {
	return s.db.GetUserChannelCount(ctx, userID)
}

// GetUserChannelLimit gets the channel limit for a user based on their flags
func (s *Service) GetUserChannelLimit(ctx context.Context, arg GetUserChannelLimitParams) (int32, error) {
	return s.db.GetUserChannelLimit(ctx, arg)
}

// GetUserChannelMemberships gets enhanced channel membership information for a user
func (s *Service) GetUserChannelMemberships(ctx context.Context, userID int32) ([]GetUserChannelMembershipsRow, error) {
	return s.db.GetUserChannelMemberships(ctx, userID)
}

// GetUserChannels gets a user's channels
func (s *Service) GetUserChannels(ctx context.Context, userID int32) ([]GetUserChannelsRow, error) {
	return s.db.GetUserChannels(ctx, userID)
}

// GetUserNoregDetails gets detailed NOREG information for a user
func (s *Service) GetUserNoregDetails(ctx context.Context, lower string) (GetUserNoregDetailsRow, error) {
	return s.db.GetUserNoregDetails(ctx, lower)
}

// GetUserPendingRegistrations returns the count of pending channel registrations for a user
func (s *Service) GetUserPendingRegistrations(ctx context.Context, managerID pgtype.Int4) (int64, error) {
	return s.db.GetUserPendingRegistrations(ctx, managerID)
}

// GetUsersByUsernames gets users by usernames
func (s *Service) GetUsersByUsernames(ctx context.Context, userids []string) ([]GetUsersByUsernamesRow, error) {
	return s.db.GetUsersByUsernames(ctx, userids)
}

// GetWhiteListByIP returns a whitelist entry by IP if it exists
func (s *Service) GetWhiteListByIP(ctx context.Context, ip netip.Addr) (Whitelist, error) {
	return s.db.GetWhiteListByIP(ctx, ip)
}

// InvalidateUserPasswordResetTokens invalidates all password reset tokens for a user
func (s *Service) InvalidateUserPasswordResetTokens(ctx context.Context, userID pgtype.Int4, lastUpdated int32) error {
	return s.db.InvalidateUserPasswordResetTokens(ctx, userID, lastUpdated)
}

// ListPendingUsers lists all pending users
func (s *Service) ListPendingUsers(ctx context.Context) ([]Pendinguser, error) {
	return s.db.ListPendingUsers(ctx)
}

// ListRoles lists all roles
func (s *Service) ListRoles(ctx context.Context) ([]Role, error) {
	return s.db.ListRoles(ctx)
}

// ListUserRoles lists user roles
func (s *Service) ListUserRoles(ctx context.Context, userID int32) ([]Role, error) {
	return s.db.ListUserRoles(ctx, userID)
}

// MarkPasswordResetTokenAsUsed marks a password reset token as used
func (s *Service) MarkPasswordResetTokenAsUsed(ctx context.Context, arg MarkPasswordResetTokenAsUsedParams) error {
	return s.db.MarkPasswordResetTokenAsUsed(ctx, arg)
}

// RemoveChannelMember removes a member from a channel
func (s *Service) RemoveChannelMember(
	ctx context.Context,
	arg RemoveChannelMemberParams,
) (RemoveChannelMemberRow, error) {
	return s.db.RemoveChannelMember(ctx, arg)
}

// RemoveUserRole removes a user role
func (s *Service) RemoveUserRole(ctx context.Context, userID int32, roleID int32) error {
	return s.db.RemoveUserRole(ctx, userID, roleID)
}

// RemoveUsersFromRole removes users from a role
func (s *Service) RemoveUsersFromRole(ctx context.Context, userIDs []int32, roleID int32) error {
	return s.db.RemoveUsersFromRole(ctx, userIDs, roleID)
}

// SearchChannels searches for channels by name with pagination
func (s *Service) SearchChannels(ctx context.Context, arg SearchChannelsParams) ([]SearchChannelsRow, error) {
	return s.db.SearchChannels(ctx, arg)
}

// SearchChannelsCount returns the total count of channels matching the search criteria
func (s *Service) SearchChannelsCount(ctx context.Context, name string) (int64, error) {
	return s.db.SearchChannelsCount(ctx, name)
}

// SoftDeleteChannel soft deletes a channel by setting registered_ts to 0
func (s *Service) SoftDeleteChannel(ctx context.Context, id int32) error {
	return s.db.SoftDeleteChannel(ctx, id)
}

// UpdateChannelRegistrationStatus updates channel registration related timestamps and status
func (s *Service) UpdateChannelRegistrationStatus(ctx context.Context, id int32) error {
	return s.db.UpdateChannelRegistrationStatus(ctx, id)
}

// UpdateChannelSettings updates channel description and URL
func (s *Service) UpdateChannelSettings(
	ctx context.Context,
	arg UpdateChannelSettingsParams,
) (UpdateChannelSettingsRow, error) {
	return s.db.UpdateChannelSettings(ctx, arg)
}

// UpdatePendingChannelDescription updates the description of a pending channel registration
func (s *Service) UpdatePendingChannelDescription(ctx context.Context, channelID int32, description pgtype.Text) error {
	return s.db.UpdatePendingChannelDescription(ctx, channelID, description)
}

// UpdatePendingChannelStatus updates the status of a pending channel registration
func (s *Service) UpdatePendingChannelStatus(
	ctx context.Context,
	arg UpdatePendingChannelStatusParams,
) (UpdatePendingChannelStatusRow, error) {
	return s.db.UpdatePendingChannelStatus(ctx, arg)
}

// UpdateRole updates a role
func (s *Service) UpdateRole(ctx context.Context, arg UpdateRoleParams) error {
	return s.db.UpdateRole(ctx, arg)
}

// UpdateUserFlags updates a user's flags
func (s *Service) UpdateUserFlags(ctx context.Context, arg UpdateUserFlagsParams) error {
	return s.db.UpdateUserFlags(ctx, arg)
}

// UpdateUserLastSeen updates user's last seen timestamp
func (s *Service) UpdateUserLastSeen(ctx context.Context, userID int32) error {
	return s.db.UpdateUserLastSeen(ctx, userID)
}

// UpdateUserPassword updates a user's password
func (s *Service) UpdateUserPassword(ctx context.Context, arg UpdateUserPasswordParams) error {
	return s.db.UpdateUserPassword(ctx, arg)
}

// UpdateUserTotpKey updates a user's TOTP key
func (s *Service) UpdateUserTotpKey(ctx context.Context, arg UpdateUserTotpKeyParams) error {
	return s.db.UpdateUserTotpKey(ctx, arg)
}

// ValidatePasswordResetToken validates a password reset token
func (s *Service) ValidatePasswordResetToken(
	ctx context.Context,
	token string,
	expiresAt int32,
) (PasswordResetToken, error) {
	return s.db.ValidatePasswordResetToken(ctx, token, expiresAt)
}

// GetUserBackupCodes gets user's backup codes and read status
func (s *Service) GetUserBackupCodes(ctx context.Context, id int32) (GetUserBackupCodesRow, error) {
	return s.db.GetUserBackupCodes(ctx, id)
}

// MarkBackupCodesAsRead marks backup codes as read after user has seen them
func (s *Service) MarkBackupCodesAsRead(ctx context.Context, arg MarkBackupCodesAsReadParams) error {
	return s.db.MarkBackupCodesAsRead(ctx, arg)
}

// UpdateUserBackupCodes updates user's backup codes and marks them as unread
func (s *Service) UpdateUserBackupCodes(ctx context.Context, arg UpdateUserBackupCodesParams) error {
	return s.db.UpdateUserBackupCodes(ctx, arg)
}

// WithTx returns a new Service instance that wraps the provided transaction
func (s *Service) WithTx(tx pgx.Tx) ServiceInterface {
	return &Service{
		db: s.db.WithTx(tx),
	}
}
