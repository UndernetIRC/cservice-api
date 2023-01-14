// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package totp

import (
	"math"
	"time"

	"github.com/undernetirc/cservice-api/internal/auth/oath"
)

type TOTP struct {
	oath.OTP
	interval uint64
}

func New(seed string, len int, interval uint64) *TOTP {
	otp := oath.New(seed, len)
	return &TOTP{OTP: otp, interval: interval}
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
	//TODO: implement time skew support
	counter := uint64(math.Floor(float64(t.Unix()) / float64(totp.interval)))
	return otp == totp.GenerateOTP(counter)
}
