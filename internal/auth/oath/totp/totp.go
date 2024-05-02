// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023-2024 UnderNET

package totp

import (
	"math"
	"time"

	"github.com/undernetirc/cservice-api/internal/auth/oath"
)

type TOTP struct {
	oath.OTP
	interval uint64
	skew     uint
}

func New(seed string, len int, interval uint64, skew uint) *TOTP {
	otp := oath.New(seed, len)
	return &TOTP{OTP: otp, interval: interval, skew: skew}
}

func (totp *TOTP) Generate() string {
	return totp.GenerateCustom(time.Now().UTC())
}

func (totp *TOTP) GenerateCustom(t time.Time) string {
	counter := uint64(math.Floor(float64(t.Unix()) / float64(totp.interval)))
	return totp.GenerateOTP(counter)
}

func (totp *TOTP) Validate(otp string) bool {
	return totp.ValidateCustom(otp, time.Now().UTC())
}

func (totp *TOTP) ValidateCustom(otp string, t time.Time) bool {
	counters := []uint64{}
	counter := uint64(math.Floor(float64(t.Unix()) / float64(totp.interval)))
	counters = append(counters, counter)

	for i := 1; i <= int(totp.skew); i++ {
		counters = append(counters, counter+uint64(i))
		counters = append(counters, counter-uint64(i))
	}

	for _, c := range counters {
		if otp == totp.GenerateOTP(c) {
			return true
		}
	}

	return false
}
