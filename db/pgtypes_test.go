// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

package db

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
)

func TestNewString(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  pgtype.Text
	}{
		{
			name:  "empty string",
			input: "",
			want:  pgtype.Text{String: "", Valid: true},
		},
		{
			name:  "non-empty string",
			input: "test",
			want:  pgtype.Text{String: "test", Valid: true},
		},
		{
			name:  "string with special characters",
			input: "test!@#$%^&*()",
			want:  pgtype.Text{String: "test!@#$%^&*()", Valid: true},
		},
		{
			name:  "unicode string",
			input: "测试",
			want:  pgtype.Text{String: "测试", Valid: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewString(tt.input)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.input, got.String)
			assert.True(t, got.Valid)
		})
	}
}

func TestNewTimestamp(t *testing.T) {
	tests := []struct {
		name  string
		input time.Time
	}{
		{
			name:  "current time",
			input: time.Now(),
		},
		{
			name:  "unix epoch",
			input: time.Unix(0, 0),
		},
		{
			name:  "future time",
			input: time.Now().Add(24 * time.Hour),
		},
		{
			name:  "past time",
			input: time.Now().Add(-24 * time.Hour),
		},
		{
			name:  "time with nanoseconds",
			input: time.Date(2023, 5, 15, 12, 30, 45, 123456789, time.UTC),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewTimestamp(tt.input)

			assert.Equal(t, tt.input, got.Time)
			assert.True(t, got.Valid)

			// Since Time objects can have microsecond precision differences when compared directly,
			// also check that the Unix timestamps match
			assert.Equal(t, tt.input.Unix(), got.Time.Unix())

			// Verify the pgtype.Timestamp is properly set with expected values
			expected := pgtype.Timestamp{Time: tt.input, Valid: true}
			assert.Equal(t, expected, got)
		})
	}
}
