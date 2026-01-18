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

func TestTextToString(t *testing.T) {
	tests := []struct {
		name  string
		input pgtype.Text
		want  string
	}{
		{
			name:  "valid text",
			input: pgtype.Text{String: "test", Valid: true},
			want:  "test",
		},
		{
			name:  "empty valid text",
			input: pgtype.Text{String: "", Valid: true},
			want:  "",
		},
		{
			name:  "invalid text returns empty string",
			input: pgtype.Text{String: "test", Valid: false},
			want:  "",
		},
		{
			name:  "null text returns empty string",
			input: pgtype.Text{Valid: false},
			want:  "",
		},
		{
			name:  "text with special characters",
			input: pgtype.Text{String: "test!@#$%^&*()", Valid: true},
			want:  "test!@#$%^&*()",
		},
		{
			name:  "unicode text",
			input: pgtype.Text{String: "测试", Valid: true},
			want:  "测试",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TextToString(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestInt4ToInt32(t *testing.T) {
	tests := []struct {
		name  string
		input pgtype.Int4
		want  int32
	}{
		{
			name:  "valid positive int",
			input: pgtype.Int4{Int32: 123, Valid: true},
			want:  123,
		},
		{
			name:  "valid negative int",
			input: pgtype.Int4{Int32: -456, Valid: true},
			want:  -456,
		},
		{
			name:  "valid zero",
			input: pgtype.Int4{Int32: 0, Valid: true},
			want:  0,
		},
		{
			name:  "valid max int32",
			input: pgtype.Int4{Int32: 2147483647, Valid: true},
			want:  2147483647,
		},
		{
			name:  "valid min int32",
			input: pgtype.Int4{Int32: -2147483648, Valid: true},
			want:  -2147483648,
		},
		{
			name:  "invalid int returns zero",
			input: pgtype.Int4{Int32: 123, Valid: false},
			want:  0,
		},
		{
			name:  "null int returns zero",
			input: pgtype.Int4{Valid: false},
			want:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Int4ToInt32(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestInt4ToInt(t *testing.T) {
	tests := []struct {
		name  string
		input pgtype.Int4
		want  int
	}{
		{
			name:  "valid positive int",
			input: pgtype.Int4{Int32: 123, Valid: true},
			want:  123,
		},
		{
			name:  "valid negative int",
			input: pgtype.Int4{Int32: -456, Valid: true},
			want:  -456,
		},
		{
			name:  "valid zero",
			input: pgtype.Int4{Int32: 0, Valid: true},
			want:  0,
		},
		{
			name:  "invalid int returns zero",
			input: pgtype.Int4{Int32: 123, Valid: false},
			want:  0,
		},
		{
			name:  "null int returns zero",
			input: pgtype.Int4{Valid: false},
			want:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Int4ToInt(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}
