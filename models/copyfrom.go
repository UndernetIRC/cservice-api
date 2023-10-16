// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.22.0
// source: copyfrom.go

package models

import (
	"context"
)

// iteratorForAddUsersToRole implements pgx.CopyFromSource.
type iteratorForAddUsersToRole struct {
	rows                 []AddUsersToRoleParams
	skippedFirstNextCall bool
}

func (r *iteratorForAddUsersToRole) Next() bool {
	if len(r.rows) == 0 {
		return false
	}
	if !r.skippedFirstNextCall {
		r.skippedFirstNextCall = true
		return true
	}
	r.rows = r.rows[1:]
	return len(r.rows) > 0
}

func (r iteratorForAddUsersToRole) Values() ([]interface{}, error) {
	return []interface{}{
		r.rows[0].UserID,
		r.rows[0].RoleID,
		r.rows[0].CreatedBy,
	}, nil
}

func (r iteratorForAddUsersToRole) Err() error {
	return nil
}

func (q *Queries) AddUsersToRole(ctx context.Context, arg []AddUsersToRoleParams) (int64, error) {
	return q.db.CopyFrom(ctx, []string{"user_roles"}, []string{"user_id", "role_id", "created_by"}, &iteratorForAddUsersToRole{rows: arg})
}
