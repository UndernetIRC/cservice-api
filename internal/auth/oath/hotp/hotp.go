// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package hotp

import "github.com/undernetirc/cservice-api/internal/auth/oath"

type HOTP struct {
	oath.OTP
}

func New(seed string, len int) *HOTP {
	otp := oath.New(seed, len)
	return &HOTP{OTP: otp}
}

func (h *HOTP) Generate(counter uint64) string {
	return h.GenerateOTP(counter)
}

func (h *HOTP) Validate(otp string, counter uint64) bool {
	return otp == h.Generate(counter)
}
