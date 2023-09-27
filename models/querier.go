// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.18.0

package models

import (
	"context"
	"net/netip"

	"github.com/jackc/pgx/v5/pgtype"
)

type Querier interface {
	AddUserRole(ctx context.Context, arg AddUserRoleParams) error
	AddUsersToRoles(ctx context.Context, arg []AddUsersToRolesParams) (int64, error)
	CheckEmailExists(ctx context.Context, email string) ([]pgtype.Text, error)
	CheckUsernameExists(ctx context.Context, username string) ([]string, error)
	CreatePendingUser(ctx context.Context, arg CreatePendingUserParams) (pgtype.Text, error)
	CreateRole(ctx context.Context, arg CreateRoleParams) (Role, error)
	CreateUser(ctx context.Context, arg CreateUserParams) (User, error)
	DeletePendingUserByCookie(ctx context.Context, cookie pgtype.Text) error
	DeleteRole(ctx context.Context, id int32) error
	GetAdminLevel(ctx context.Context, userID int32) (GetAdminLevelRow, error)
	GetGlineByIP(ctx context.Context, host string) (Gline, error)
	GetRoleByID(ctx context.Context, id int32) (Role, error)
	GetRoleByName(ctx context.Context, name string) (Role, error)
	GetUser(ctx context.Context, arg GetUserParams) (GetUserRow, error)
	GetUserByEmail(ctx context.Context, email string) (User, error)
	GetUserByID(ctx context.Context, id int32) (GetUserByIDRow, error)
	GetUserByUsername(ctx context.Context, username string) (User, error)
	GetUserChannels(ctx context.Context, userID int32) ([]GetUserChannelsRow, error)
	GetUsersByUsernames(ctx context.Context, userids []string) ([]GetUsersByUsernamesRow, error)
	GetWhiteListByIP(ctx context.Context, ip netip.Addr) (Whitelist, error)
	ListPendingUsers(ctx context.Context) ([]Pendinguser, error)
	ListRoles(ctx context.Context) ([]Role, error)
	ListUserRoles(ctx context.Context, userID int32) ([]Role, error)
	RemoveMultipleUserRoles(ctx context.Context, arg RemoveMultipleUserRolesParams) error
	RemoveUserRole(ctx context.Context, arg RemoveUserRoleParams) error
	UpdateRole(ctx context.Context, arg UpdateRoleParams) error
}

var _ Querier = (*Queries)(nil)
