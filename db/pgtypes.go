// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

// Package db defines the database types and functions.
package db

import (
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

// NewString returns a new pgtype.Text
func NewString(s string) pgtype.Text {
	return pgtype.Text{String: s, Valid: true}
}

// NewTimestamp returns a new pgtype.Timestamp
func NewTimestamp(t time.Time) pgtype.Timestamp {
	return pgtype.Timestamp{Time: t, Valid: true}
}

func NewInt4(t int64) pgtype.Int4 {
	return pgtype.Int4{Int32: int32(t), Valid: true}
}
