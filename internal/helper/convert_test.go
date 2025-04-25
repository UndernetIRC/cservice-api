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
