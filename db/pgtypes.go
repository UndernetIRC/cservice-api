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
	const (
		maxInt32 = 2147483647
		minInt32 = -2147483648
	)

	var result int32
	if t > maxInt32 {
		result = maxInt32
	} else if t < minInt32 {
		result = minInt32
	} else {
		result = int32(t) // #nosec G115 - safe conversion after bounds check
	}

	return pgtype.Int4{Int32: result, Valid: true}
}
