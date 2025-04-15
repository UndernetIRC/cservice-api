// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023-2024 UnderNET

package oath

import (
	"encoding/base32"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test vectors from RFC 4226
const (
	testSecret = "12345678901234567890"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name      string
		seed      string
		otpLength int
		wantErr   bool
	}{
		{
			name:      "empty seed generates random seed",
			seed:      "",
			otpLength: 6,
			wantErr:   false,
		},
		{
			name:      "valid seed is preserved",
			seed:      "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
			otpLength: 6,
			wantErr:   false,
		},
		{
			name:      "valid seed with different OTP length",
			seed:      "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
			otpLength: 8,
			wantErr:   false,
		},
		{
			name:      "invalid base32 seed",
			seed:      "invalid-base32!@#$",
			otpLength: 6,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr {
				assert.Panics(t, func() {
					New(tt.seed, tt.otpLength)
				})
				return
			}

			otp := New(tt.seed, tt.otpLength)
			if tt.seed == "" {
				assert.NotEmpty(t, otp.GetSeed())
				assert.Equal(t, tt.otpLength, otp.otpLength)
			} else {
				assert.Equal(t, tt.seed, otp.GetSeed())
				assert.Equal(t, tt.otpLength, otp.otpLength)
			}
		})
	}
}

func TestGenerateOTP(t *testing.T) {
	// Test vectors from RFC 4226
	secret := base32.StdEncoding.EncodeToString([]byte(testSecret))
	otp := New(secret, 6)

	tests := []struct {
		name  string
		input uint64
		want  string
	}{
		{
			name:  "counter 0",
			input: 0,
			want:  "755224",
		},
		{
			name:  "counter 1",
			input: 1,
			want:  "287082",
		},
		{
			name:  "counter 2",
			input: 2,
			want:  "359152",
		},
		{
			name:  "counter 3",
			input: 3,
			want:  "969429",
		},
		{
			name:  "counter 4",
			input: 4,
			want:  "338314",
		},
		{
			name:  "counter 5",
			input: 5,
			want:  "254676",
		},
		{
			name:  "counter 6",
			input: 6,
			want:  "287922",
		},
		{
			name:  "counter 7",
			input: 7,
			want:  "162583",
		},
		{
			name:  "counter 8",
			input: 8,
			want:  "399871",
		},
		{
			name:  "counter 9",
			input: 9,
			want:  "520489",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := otp.GenerateOTP(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGenerateOTPDifferentLengths(t *testing.T) {
	secret := base32.StdEncoding.EncodeToString([]byte(testSecret))

	tests := []struct {
		name      string
		otpLength int
		input     uint64
		wantLen   int
	}{
		{
			name:      "6 digits",
			otpLength: 6,
			input:     0,
			wantLen:   6,
		},
		{
			name:      "8 digits",
			otpLength: 8,
			input:     0,
			wantLen:   8,
		},
		{
			name:      "4 digits",
			otpLength: 4,
			input:     0,
			wantLen:   4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			otp := New(secret, tt.otpLength)
			got := otp.GenerateOTP(tt.input)
			assert.Equal(t, tt.wantLen, len(got))
		})
	}
}

func TestGetSeed(t *testing.T) {
	tests := []struct {
		name string
		seed string
		want string
	}{
		{
			name: "empty seed returns random seed",
			seed: "",
			want: "",
		},
		{
			name: "valid seed is returned",
			seed: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
			want: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			otp := New(tt.seed, 6)
			got := otp.GetSeed()
			if tt.want == "" {
				assert.NotEmpty(t, got)
			} else {
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestDecodeSeed(t *testing.T) {
	tests := []struct {
		name    string
		seed    string
		wantErr bool
	}{
		{
			name:    "valid base32 seed",
			seed:    "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
			wantErr: false,
		},
		{
			name:    "valid base32 seed with padding",
			seed:    "GEZDGNBVGY3TQOJQ",
			wantErr: false,
		},
		{
			name:    "valid base32 seed lowercase",
			seed:    "gezdgnbvg3tqojq",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			otp := New(tt.seed, 6)
			got := otp.decodeSeed()
			assert.NotEmpty(t, got)
		})
	}
}

func TestItob(t *testing.T) {
	tests := []struct {
		name  string
		input uint64
		want  []byte
	}{
		{
			name:  "zero",
			input: 0,
			want:  []byte{0, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			name:  "one",
			input: 1,
			want:  []byte{0, 0, 0, 0, 0, 0, 0, 1},
		},
		{
			name:  "max uint64",
			input: ^uint64(0),
			want:  []byte{255, 255, 255, 255, 255, 255, 255, 255},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			otp := New("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 6)
			got := otp.itob(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}
