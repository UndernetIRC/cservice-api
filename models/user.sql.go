// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.29.0
// source: user.sql

package models

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/undernetirc/cservice-api/db/types/flags"
	"github.com/undernetirc/cservice-api/db/types/password"
)

const createUser = `-- name: CreateUser :one
INSERT INTO users (user_name, password, flags, email, last_updated, last_updated_by, language_id, question_id, verificationdata, post_forms, signup_ts, signup_ip, maxlogins)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
RETURNING id, user_name, password, email, url, question_id, verificationdata, language_id, public_key, post_forms, flags, last_updated_by, last_updated, deleted, tz_setting, signup_cookie, signup_ts, signup_ip, maxlogins, totp_key
`

type CreateUserParams struct {
	Username         string            `json:"user_name"`
	Password         password.Password `json:"password"`
	Flags            flags.User        `json:"flags"`
	Email            pgtype.Text       `json:"email"`
	LastUpdated      int32             `json:"last_updated"`
	LastUpdatedBy    pgtype.Text       `json:"last_updated_by"`
	LanguageID       pgtype.Int4       `json:"language_id"`
	QuestionID       pgtype.Int2       `json:"question_id"`
	Verificationdata pgtype.Text       `json:"verificationdata"`
	PostForms        int32             `json:"post_forms"`
	SignupTs         pgtype.Int4       `json:"signup_ts"`
	SignupIp         pgtype.Text       `json:"signup_ip"`
	Maxlogins        pgtype.Int4       `json:"maxlogins"`
}

func (q *Queries) CreateUser(ctx context.Context, arg CreateUserParams) (User, error) {
	row := q.db.QueryRow(ctx, createUser,
		arg.Username,
		arg.Password,
		arg.Flags,
		arg.Email,
		arg.LastUpdated,
		arg.LastUpdatedBy,
		arg.LanguageID,
		arg.QuestionID,
		arg.Verificationdata,
		arg.PostForms,
		arg.SignupTs,
		arg.SignupIp,
		arg.Maxlogins,
	)
	var i User
	err := row.Scan(
		&i.ID,
		&i.Username,
		&i.Password,
		&i.Email,
		&i.Url,
		&i.QuestionID,
		&i.Verificationdata,
		&i.LanguageID,
		&i.PublicKey,
		&i.PostForms,
		&i.Flags,
		&i.LastUpdatedBy,
		&i.LastUpdated,
		&i.Deleted,
		&i.TzSetting,
		&i.SignupCookie,
		&i.SignupTs,
		&i.SignupIp,
		&i.Maxlogins,
		&i.TotpKey,
	)
	return i, err
}

const getAdminLevel = `-- name: GetAdminLevel :one
SELECT l.access, l.suspend_expires
FROM channels c
  INNER JOIN levels l
    ON c.id = l.channel_id
WHERE c.name = '*' AND l.user_id=$1
`

type GetAdminLevelRow struct {
	Access         int32       `json:"access"`
	SuspendExpires pgtype.Int4 `json:"suspend_expires"`
}

func (q *Queries) GetAdminLevel(ctx context.Context, userID int32) (GetAdminLevelRow, error) {
	row := q.db.QueryRow(ctx, getAdminLevel, userID)
	var i GetAdminLevelRow
	err := row.Scan(&i.Access, &i.SuspendExpires)
	return i, err
}

const getUser = `-- name: GetUser :one
SELECT u.id, u.user_name, u.password, u.email, u.url, u.question_id, u.verificationdata, u.language_id, u.public_key, u.post_forms, u.flags, u.last_updated_by, u.last_updated, u.deleted, u.tz_setting, u.signup_cookie, u.signup_ts, u.signup_ip, u.maxlogins, u.totp_key, ul.last_seen, l.code as language_code, l.name as language_name
FROM users u
       INNER JOIN users_lastseen ul ON u.id = ul.user_id
       INNER JOIN languages l ON u.language_id = l.id
WHERE CASE WHEN LENGTH($1::text) != 0 THEN  lower(u.user_name) = lower($1) ELSE true END
  AND CASE WHEN LENGTH($2::text) != 0 THEN lower(u.email) = lower($2) ELSE true END
  AND CASE WHEN $3::int4 > 0 THEN u.id = $3 ELSE true END
LIMIT 1
`

type GetUserParams struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	ID       int32  `json:"id"`
}

type GetUserRow struct {
	ID               int32             `json:"id"`
	Username         string            `json:"user_name"`
	Password         password.Password `json:"password"`
	Email            pgtype.Text       `json:"email"`
	Url              pgtype.Text       `json:"url"`
	QuestionID       pgtype.Int2       `json:"question_id"`
	Verificationdata pgtype.Text       `json:"verificationdata"`
	LanguageID       pgtype.Int4       `json:"language_id"`
	PublicKey        pgtype.Text       `json:"public_key"`
	PostForms        int32             `json:"post_forms"`
	Flags            flags.User        `json:"flags"`
	LastUpdatedBy    pgtype.Text       `json:"last_updated_by"`
	LastUpdated      int32             `json:"last_updated"`
	Deleted          pgtype.Int2       `json:"deleted"`
	TzSetting        pgtype.Text       `json:"tz_setting"`
	SignupCookie     pgtype.Text       `json:"signup_cookie"`
	SignupTs         pgtype.Int4       `json:"signup_ts"`
	SignupIp         pgtype.Text       `json:"signup_ip"`
	Maxlogins        pgtype.Int4       `json:"maxlogins"`
	TotpKey          pgtype.Text       `json:"totp_key"`
	LastSeen         pgtype.Int4       `json:"last_seen"`
	LanguageCode     pgtype.Text       `json:"language_code"`
	LanguageName     pgtype.Text       `json:"language_name"`
}

func (q *Queries) GetUser(ctx context.Context, arg GetUserParams) (GetUserRow, error) {
	row := q.db.QueryRow(ctx, getUser, arg.Username, arg.Email, arg.ID)
	var i GetUserRow
	err := row.Scan(
		&i.ID,
		&i.Username,
		&i.Password,
		&i.Email,
		&i.Url,
		&i.QuestionID,
		&i.Verificationdata,
		&i.LanguageID,
		&i.PublicKey,
		&i.PostForms,
		&i.Flags,
		&i.LastUpdatedBy,
		&i.LastUpdated,
		&i.Deleted,
		&i.TzSetting,
		&i.SignupCookie,
		&i.SignupTs,
		&i.SignupIp,
		&i.Maxlogins,
		&i.TotpKey,
		&i.LastSeen,
		&i.LanguageCode,
		&i.LanguageName,
	)
	return i, err
}

const getUserByEmail = `-- name: GetUserByEmail :one
SELECT id, user_name, password, email, url, question_id, verificationdata, language_id, public_key, post_forms, flags, last_updated_by, last_updated, deleted, tz_setting, signup_cookie, signup_ts, signup_ip, maxlogins, totp_key
FROM users
WHERE lower(email) = lower($1) LIMIT 1
`

func (q *Queries) GetUserByEmail(ctx context.Context, email string) (User, error) {
	row := q.db.QueryRow(ctx, getUserByEmail, email)
	var i User
	err := row.Scan(
		&i.ID,
		&i.Username,
		&i.Password,
		&i.Email,
		&i.Url,
		&i.QuestionID,
		&i.Verificationdata,
		&i.LanguageID,
		&i.PublicKey,
		&i.PostForms,
		&i.Flags,
		&i.LastUpdatedBy,
		&i.LastUpdated,
		&i.Deleted,
		&i.TzSetting,
		&i.SignupCookie,
		&i.SignupTs,
		&i.SignupIp,
		&i.Maxlogins,
		&i.TotpKey,
	)
	return i, err
}

const getUserByID = `-- name: GetUserByID :one
SELECT u.id, u.user_name, u.password, u.email, u.url, u.question_id, u.verificationdata, u.language_id, u.public_key, u.post_forms, u.flags, u.last_updated_by, u.last_updated, u.deleted, u.tz_setting, u.signup_cookie, u.signup_ts, u.signup_ip, u.maxlogins, u.totp_key, ul.last_seen, l.code as language_code, l.name as language_name
FROM users u
INNER JOIN users_lastseen ul ON u.id = ul.user_id
INNER JOIN languages l ON u.language_id = l.id
WHERE u.id = $1 LIMIT 1
`

type GetUserByIDRow struct {
	ID               int32             `json:"id"`
	Username         string            `json:"user_name"`
	Password         password.Password `json:"password"`
	Email            pgtype.Text       `json:"email"`
	Url              pgtype.Text       `json:"url"`
	QuestionID       pgtype.Int2       `json:"question_id"`
	Verificationdata pgtype.Text       `json:"verificationdata"`
	LanguageID       pgtype.Int4       `json:"language_id"`
	PublicKey        pgtype.Text       `json:"public_key"`
	PostForms        int32             `json:"post_forms"`
	Flags            flags.User        `json:"flags"`
	LastUpdatedBy    pgtype.Text       `json:"last_updated_by"`
	LastUpdated      int32             `json:"last_updated"`
	Deleted          pgtype.Int2       `json:"deleted"`
	TzSetting        pgtype.Text       `json:"tz_setting"`
	SignupCookie     pgtype.Text       `json:"signup_cookie"`
	SignupTs         pgtype.Int4       `json:"signup_ts"`
	SignupIp         pgtype.Text       `json:"signup_ip"`
	Maxlogins        pgtype.Int4       `json:"maxlogins"`
	TotpKey          pgtype.Text       `json:"totp_key"`
	LastSeen         pgtype.Int4       `json:"last_seen"`
	LanguageCode     pgtype.Text       `json:"language_code"`
	LanguageName     pgtype.Text       `json:"language_name"`
}

func (q *Queries) GetUserByID(ctx context.Context, id int32) (GetUserByIDRow, error) {
	row := q.db.QueryRow(ctx, getUserByID, id)
	var i GetUserByIDRow
	err := row.Scan(
		&i.ID,
		&i.Username,
		&i.Password,
		&i.Email,
		&i.Url,
		&i.QuestionID,
		&i.Verificationdata,
		&i.LanguageID,
		&i.PublicKey,
		&i.PostForms,
		&i.Flags,
		&i.LastUpdatedBy,
		&i.LastUpdated,
		&i.Deleted,
		&i.TzSetting,
		&i.SignupCookie,
		&i.SignupTs,
		&i.SignupIp,
		&i.Maxlogins,
		&i.TotpKey,
		&i.LastSeen,
		&i.LanguageCode,
		&i.LanguageName,
	)
	return i, err
}

const getUserByUsername = `-- name: GetUserByUsername :one
SELECT id, user_name, password, email, url, question_id, verificationdata, language_id, public_key, post_forms, flags, last_updated_by, last_updated, deleted, tz_setting, signup_cookie, signup_ts, signup_ip, maxlogins, totp_key
FROM users
WHERE lower(user_name) = lower($1) LIMIT 1
`

func (q *Queries) GetUserByUsername(ctx context.Context, username string) (User, error) {
	row := q.db.QueryRow(ctx, getUserByUsername, username)
	var i User
	err := row.Scan(
		&i.ID,
		&i.Username,
		&i.Password,
		&i.Email,
		&i.Url,
		&i.QuestionID,
		&i.Verificationdata,
		&i.LanguageID,
		&i.PublicKey,
		&i.PostForms,
		&i.Flags,
		&i.LastUpdatedBy,
		&i.LastUpdated,
		&i.Deleted,
		&i.TzSetting,
		&i.SignupCookie,
		&i.SignupTs,
		&i.SignupIp,
		&i.Maxlogins,
		&i.TotpKey,
	)
	return i, err
}

const getUserChannels = `-- name: GetUserChannels :many
SELECT c.name, l.channel_id, l.user_id, l.access, l.flags, l.last_modif, l.suspend_expires, l.suspend_by
FROM levels l
INNER JOIN channels c
ON l.channel_id = c.id
WHERE l.user_id = $1
`

type GetUserChannelsRow struct {
	Name           string      `json:"name"`
	ChannelID      int32       `json:"channel_id"`
	UserID         int32       `json:"user_id"`
	Access         int32       `json:"access"`
	Flags          int16       `json:"flags"`
	LastModif      pgtype.Int4 `json:"last_modif"`
	SuspendExpires pgtype.Int4 `json:"suspend_expires"`
	SuspendBy      pgtype.Text `json:"suspend_by"`
}

func (q *Queries) GetUserChannels(ctx context.Context, userID int32) ([]GetUserChannelsRow, error) {
	rows, err := q.db.Query(ctx, getUserChannels, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []GetUserChannelsRow{}
	for rows.Next() {
		var i GetUserChannelsRow
		if err := rows.Scan(
			&i.Name,
			&i.ChannelID,
			&i.UserID,
			&i.Access,
			&i.Flags,
			&i.LastModif,
			&i.SuspendExpires,
			&i.SuspendBy,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getUsersByUsernames = `-- name: GetUsersByUsernames :many
SELECT u.id, u.user_name, u.password, u.email, u.url, u.question_id, u.verificationdata, u.language_id, u.public_key, u.post_forms, u.flags, u.last_updated_by, u.last_updated, u.deleted, u.tz_setting, u.signup_cookie, u.signup_ts, u.signup_ip, u.maxlogins, u.totp_key, ul.last_seen, l.code as language_code, l.name as language_name
FROM users u
INNER JOIN users_lastseen ul
ON u.id = ul.user_id
INNER JOIN languages l
ON u.language_id = l.id
WHERE u.user_name ILIKE ANY($1::VARCHAR[])
`

type GetUsersByUsernamesRow struct {
	ID               int32             `json:"id"`
	Username         string            `json:"user_name"`
	Password         password.Password `json:"password"`
	Email            pgtype.Text       `json:"email"`
	Url              pgtype.Text       `json:"url"`
	QuestionID       pgtype.Int2       `json:"question_id"`
	Verificationdata pgtype.Text       `json:"verificationdata"`
	LanguageID       pgtype.Int4       `json:"language_id"`
	PublicKey        pgtype.Text       `json:"public_key"`
	PostForms        int32             `json:"post_forms"`
	Flags            flags.User        `json:"flags"`
	LastUpdatedBy    pgtype.Text       `json:"last_updated_by"`
	LastUpdated      int32             `json:"last_updated"`
	Deleted          pgtype.Int2       `json:"deleted"`
	TzSetting        pgtype.Text       `json:"tz_setting"`
	SignupCookie     pgtype.Text       `json:"signup_cookie"`
	SignupTs         pgtype.Int4       `json:"signup_ts"`
	SignupIp         pgtype.Text       `json:"signup_ip"`
	Maxlogins        pgtype.Int4       `json:"maxlogins"`
	TotpKey          pgtype.Text       `json:"totp_key"`
	LastSeen         pgtype.Int4       `json:"last_seen"`
	LanguageCode     pgtype.Text       `json:"language_code"`
	LanguageName     pgtype.Text       `json:"language_name"`
}

func (q *Queries) GetUsersByUsernames(ctx context.Context, userids []string) ([]GetUsersByUsernamesRow, error) {
	rows, err := q.db.Query(ctx, getUsersByUsernames, userids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []GetUsersByUsernamesRow{}
	for rows.Next() {
		var i GetUsersByUsernamesRow
		if err := rows.Scan(
			&i.ID,
			&i.Username,
			&i.Password,
			&i.Email,
			&i.Url,
			&i.QuestionID,
			&i.Verificationdata,
			&i.LanguageID,
			&i.PublicKey,
			&i.PostForms,
			&i.Flags,
			&i.LastUpdatedBy,
			&i.LastUpdated,
			&i.Deleted,
			&i.TzSetting,
			&i.SignupCookie,
			&i.SignupTs,
			&i.SignupIp,
			&i.Maxlogins,
			&i.TotpKey,
			&i.LastSeen,
			&i.LanguageCode,
			&i.LanguageName,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}
