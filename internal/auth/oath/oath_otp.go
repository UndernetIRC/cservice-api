// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023-2024 UnderNET

package oath

import (
	"crypto/hmac"
	"crypto/rand"

	// SHA1 is required by RFC 4226 (HOTP) and RFC 6238 (TOTP)
	// nolint:gosec // SHA1 is used as part of HMAC-SHA1 which is still secure for this use case
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"math"
	"strings"
)

type OTP struct {
	seed      string
	otpLength int
}

func New(seed string, otpLength int) OTP {
	if seed == "" {
		secret := make([]byte, 20)
		_, err := rand.Reader.Read(secret)
		if err != nil {
			panic(err)
		}
		seed = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
	}
	return OTP{
		seed:      seed,
		otpLength: otpLength,
	}
}

func (otp *OTP) GenerateOTP(input uint64) string {
	h := hmac.New(sha1.New, otp.decodeSeed())
	h.Write(otp.itob(input))
	s := h.Sum(nil)
	o := s[len(s)-1] & 0xf
	v := binary.BigEndian.Uint32(s[o : o+4])
	v &= 0x7fffffff
	//v := uint32(((int(s[o]) & 0x7f) << 24) |
	//	((int(s[o+1]) & 0xff) << 16) |
	//	((int(s[o+2]) & 0xff) << 8) |
	//	(int(s[o+3]) & 0xff))

	// Fix the integer overflow potential
	modulus := uint32(math.Pow10(otp.otpLength))
	code := v % modulus

	return fmt.Sprintf(fmt.Sprintf("%%0%dd", otp.otpLength), code)
}

func (otp *OTP) GetSeed() string {
	return otp.seed
}

func (otp *OTP) decodeSeed() []byte {
	var seed []byte
	var err error

	s := strings.TrimSpace(otp.seed)
	if n := len(s) % 8; n != 0 {
		s = s + strings.Repeat("=", 8-n)
	}
	s = strings.ToUpper(s)
	seed, err = base32.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}

	return seed
}

func (otp *OTP) itob(input uint64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, input)
	return buf
}
