// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.18.0
// source: gline.sql

package models

import (
	"context"
)

const getGlineByIP = `-- name: GetGlineByIP :one
SELECT id, host, addedby, addedon, expiresat, lastupdated, reason
FROM glines
WHERE host ~ '.*@[abcdef0-9]+[\.:]+' AND split_part(host, '@', 2)::INET >>= $1
LIMIT 1
`

func (q *Queries) GetGlineByIP(ctx context.Context, host string) (Gline, error) {
	row := q.db.QueryRow(ctx, getGlineByIP, host)
	var i Gline
	err := row.Scan(
		&i.ID,
		&i.Host,
		&i.Addedby,
		&i.Addedon,
		&i.Expiresat,
		&i.Lastupdated,
		&i.Reason,
	)
	return i, err
}
