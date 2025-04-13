// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023-2024 UnderNET

// Package totp provides a time-based one-time password (TOTP) implementation.
package totp

import (
	"math"
	"time"

	"github.com/undernetirc/cservice-api/internal/auth/oath"
)

// TOTP represents a Time-based One-Time Password
type TOTP struct {
	oath.OTP
	interval uint64
	skew     uint8
}

// New creates a new TOTP instance.
func New(seed string, len int, interval uint64, skew uint8) *TOTP {
	otp := oath.New(seed, len)
	return &TOTP{OTP: otp, interval: interval, skew: skew}
}

// Generate generates a new TOTP.
func (totp *TOTP) Generate() string {
	return totp.GenerateCustom(time.Now().UTC())
}

// GenerateCustom generates a new TOTP with a custom time.
func (totp *TOTP) GenerateCustom(t time.Time) string {
	counter := uint64(math.Floor(float64(t.Unix()) / float64(totp.interval)))
	return totp.GenerateOTP(counter)
}

func (totp *TOTP) Validate(otp string) bool {
	return totp.ValidateCustom(otp, time.Now().UTC())
}

// ValidateCustom checks if the provided OTP is valid
func (totp *TOTP) ValidateCustom(otp string, t time.Time) bool {
	var now uint64
	if t.Unix() >= 0 {
		now = uint64(t.Unix()) // nolint:gosec // Safe conversion: Unix timestamp won't overflow uint64
	} else {
		now = 0
	}

	counter := now / totp.interval
	counters := []uint64{counter}

	// Since skew is now uint8, max value is 255 which is safe to convert to int
	skewInt := int(totp.skew)

	// Pre-allocate slice to avoid reallocations
	counters = make([]uint64, 0, 2*skewInt+1)
	counters = append(counters, counter)

	var i uint8
	for i = 1; i <= totp.skew; i++ {
		delta := uint64(i)

		// Since i is bounded by skewInt (max 255), these conversions are safe
		if counter >= delta { // Prevent underflow
			counters = append(counters, counter-uint64(i))
		}
		// Check for overflow
		maxDelta := math.MaxUint64 - counter
		if delta <= maxDelta {
			counters = append(counters, counter+delta)
		}
	}

	for _, c := range counters {
		if otp == totp.GenerateOTP(c) {
			return true
		}
	}
	return false
}
