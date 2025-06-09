// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2024 UnderNET

package helper

import (
	"math"
	"testing"
)

func TestSafeAtoi32(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    int32
		wantErr bool
	}{
		{
			name:    "valid positive integer",
			input:   "42",
			want:    42,
			wantErr: false,
		},
		{
			name:    "valid negative integer",
			input:   "-42",
			want:    -42,
			wantErr: false,
		},
		{
			name:    "valid zero",
			input:   "0",
			want:    0,
			wantErr: false,
		},
		{
			name:    "valid max int32",
			input:   "2147483647",
			want:    math.MaxInt32,
			wantErr: false,
		},
		{
			name:    "valid min int32",
			input:   "-2147483648",
			want:    math.MinInt32,
			wantErr: false,
		},
		{
			name:    "exceeds max int32",
			input:   "2147483648",
			want:    0,
			wantErr: true,
		},
		{
			name:    "exceeds min int32",
			input:   "-2147483649",
			want:    0,
			wantErr: true,
		},
		{
			name:    "non-numeric string",
			input:   "abc",
			want:    0,
			wantErr: true,
		},
		{
			name:    "mixed string",
			input:   "123abc",
			want:    0,
			wantErr: true,
		},
		{
			name:    "empty string",
			input:   "",
			want:    0,
			wantErr: true,
		},
		{
			name:    "floating point",
			input:   "42.5",
			want:    0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SafeAtoi32(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("SafeAtoi32() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("SafeAtoi32() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSafeInt32(t *testing.T) {
	tests := []struct {
		name     string
		input    int
		expected int32
	}{
		{
			name:     "positive value within range",
			input:    1000,
			expected: 1000,
		},
		{
			name:     "zero value",
			input:    0,
			expected: 0,
		},
		{
			name:     "negative value",
			input:    -100,
			expected: -100,
		},
		{
			name:     "max int32 value",
			input:    math.MaxInt32,
			expected: math.MaxInt32,
		},
		{
			name:     "min int32 value",
			input:    math.MinInt32,
			expected: math.MinInt32,
		},
		{
			name:     "value beyond int32 max (overflow)",
			input:    math.MaxInt32 + 1,
			expected: 0, // Function returns 0 for overflow
		},
		{
			name:     "value below int32 min (underflow)",
			input:    math.MinInt32 - 1,
			expected: 0, // Function returns 0 for underflow
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SafeInt32(tt.input)
			if result != tt.expected {
				t.Errorf("SafeInt32(%d) = %d, expected %d", tt.input, result, tt.expected)
			}
		})
	}
}

func TestSafeInt32FromInt64(t *testing.T) {
	tests := []struct {
		name     string
		input    int64
		expected int32
	}{
		{
			name:     "positive value within range",
			input:    1000,
			expected: 1000,
		},
		{
			name:     "zero value",
			input:    0,
			expected: 0,
		},
		{
			name:     "negative value",
			input:    -100,
			expected: -100,
		},
		{
			name:     "max int32 value",
			input:    math.MaxInt32,
			expected: math.MaxInt32,
		},
		{
			name:     "min int32 value",
			input:    math.MinInt32,
			expected: math.MinInt32,
		},
		{
			name:     "value beyond int32 max (overflow)",
			input:    math.MaxInt32 + 1,
			expected: 0, // Function returns 0 for overflow
		},
		{
			name:     "value below int32 min (underflow)",
			input:    math.MinInt32 - 1,
			expected: 0, // Function returns 0 for underflow
		},
		{
			name:     "large positive int64",
			input:    9223372036854775807, // math.MaxInt64
			expected: 0,                   // Function returns 0 for overflow
		},
		{
			name:     "large negative int64",
			input:    -9223372036854775808, // math.MinInt64
			expected: 0,                    // Function returns 0 for underflow
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SafeInt32FromInt64(tt.input)
			if result != tt.expected {
				t.Errorf("SafeInt32FromInt64(%d) = %d, expected %d", tt.input, result, tt.expected)
			}
		})
	}
}

func TestSafeInt64FromInt(t *testing.T) {
	tests := []struct {
		name     string
		input    int
		expected int64
	}{
		{
			name:     "positive value",
			input:    1000,
			expected: 1000,
		},
		{
			name:     "zero value",
			input:    0,
			expected: 0,
		},
		{
			name:     "negative value",
			input:    -100,
			expected: -100,
		},
		{
			name:     "max int value",
			input:    math.MaxInt,
			expected: int64(math.MaxInt),
		},
		{
			name:     "min int value",
			input:    math.MinInt,
			expected: int64(math.MinInt),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SafeInt64FromInt(tt.input)
			if result != tt.expected {
				t.Errorf("SafeInt64FromInt(%d) = %d, expected %d", tt.input, result, tt.expected)
			}
		})
	}
}

func TestSafeIntFromInt32(t *testing.T) {
	tests := []struct {
		name     string
		input    int32
		expected int
	}{
		{
			name:     "positive value",
			input:    1000,
			expected: 1000,
		},
		{
			name:     "zero value",
			input:    0,
			expected: 0,
		},
		{
			name:     "negative value",
			input:    -100,
			expected: -100,
		},
		{
			name:     "max int32 value",
			input:    math.MaxInt32,
			expected: math.MaxInt32,
		},
		{
			name:     "min int32 value",
			input:    math.MinInt32,
			expected: math.MinInt32,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SafeIntFromInt32(tt.input)
			if result != tt.expected {
				t.Errorf("SafeIntFromInt32(%d) = %d, expected %d", tt.input, result, tt.expected)
			}
		})
	}
}

func TestSafeIntFromInt64(t *testing.T) {
	tests := []struct {
		name     string
		input    int64
		expected int
	}{
		{
			name:     "positive value within range",
			input:    1000,
			expected: 1000,
		},
		{
			name:     "zero value",
			input:    0,
			expected: 0,
		},
		{
			name:     "negative value",
			input:    -100,
			expected: -100,
		},
		{
			name:     "max int value as int64",
			input:    int64(math.MaxInt),
			expected: math.MaxInt,
		},
		{
			name:     "min int value as int64",
			input:    int64(math.MinInt),
			expected: math.MinInt,
		},
		// Note: These tests depend on platform int size
		// On 64-bit platforms, int == int64, so these will not overflow
		// On 32-bit platforms, int == int32, so these will overflow
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SafeIntFromInt64(tt.input)
			if result != tt.expected {
				t.Errorf("SafeIntFromInt64(%d) = %d, expected %d", tt.input, result, tt.expected)
			}
		})
	}
}
