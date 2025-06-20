// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.29.0
// source: pendinguser.sql

package models

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/undernetirc/cservice-api/db/types/password"
)

const createPendingUser = `-- name: CreatePendingUser :one
INSERT INTO pendingusers (user_name, password, cookie, expire, email, language, question_id, verificationdata, poster_ip)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING cookie
`

type CreatePendingUserParams struct {
	Username         pgtype.Text       `json:"user_name"`
	Password         password.Password `json:"password"`
	Cookie           pgtype.Text       `json:"cookie"`
	Expire           pgtype.Int4       `json:"expire"`
	Email            pgtype.Text       `json:"email"`
	Language         pgtype.Int4       `json:"language"`
	QuestionID       pgtype.Int2       `json:"question_id"`
	Verificationdata pgtype.Text       `json:"verificationdata"`
	PosterIp         pgtype.Text       `json:"poster_ip"`
}

func (q *Queries) CreatePendingUser(ctx context.Context, arg CreatePendingUserParams) (pgtype.Text, error) {
	row := q.db.QueryRow(ctx, createPendingUser,
		arg.Username,
		arg.Password,
		arg.Cookie,
		arg.Expire,
		arg.Email,
		arg.Language,
		arg.QuestionID,
		arg.Verificationdata,
		arg.PosterIp,
	)
	var cookie pgtype.Text
	err := row.Scan(&cookie)
	return cookie, err
}

const deletePendingUserByCookie = `-- name: DeletePendingUserByCookie :exec
DELETE FROM pendingusers
WHERE cookie = $1
`

func (q *Queries) DeletePendingUserByCookie(ctx context.Context, cookie pgtype.Text) error {
	_, err := q.db.Exec(ctx, deletePendingUserByCookie, cookie)
	return err
}

const getPendingUserByCookie = `-- name: GetPendingUserByCookie :one
SELECT user_name, cookie, email, expire, question_id, verificationdata, poster_ip, language, password FROM pendingusers
WHERE cookie = $1
`

func (q *Queries) GetPendingUserByCookie(ctx context.Context, cookie pgtype.Text) (Pendinguser, error) {
	row := q.db.QueryRow(ctx, getPendingUserByCookie, cookie)
	var i Pendinguser
	err := row.Scan(
		&i.Username,
		&i.Cookie,
		&i.Email,
		&i.Expire,
		&i.QuestionID,
		&i.Verificationdata,
		&i.PosterIp,
		&i.Language,
		&i.Password,
	)
	return i, err
}

const listPendingUsers = `-- name: ListPendingUsers :many
SELECT user_name, cookie, email, expire, question_id, verificationdata, poster_ip, language, password FROM pendingusers
ORDER BY expire DESC
`

func (q *Queries) ListPendingUsers(ctx context.Context) ([]Pendinguser, error) {
	rows, err := q.db.Query(ctx, listPendingUsers)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Pendinguser{}
	for rows.Next() {
		var i Pendinguser
		if err := rows.Scan(
			&i.Username,
			&i.Cookie,
			&i.Email,
			&i.Expire,
			&i.QuestionID,
			&i.Verificationdata,
			&i.PosterIp,
			&i.Language,
			&i.Password,
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
