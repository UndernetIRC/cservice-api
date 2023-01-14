// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package auth

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"io"
)

func md5validatePassword(passwordHash string, password string) bool {
	salt := passwordHash[0:8]
	hash := passwordHash[8:]

	h := md5.New()
	_, err := io.WriteString(h, salt+password)
	if err != nil {
		panic("Hashing error")
	}

	hashBytes, err := hex.DecodeString(hash)
	if err != nil {
		panic("Hex decode string failed")
	}

	res := bytes.Compare(h.Sum(nil), hashBytes)
	if res == 0 {
		return true
	}

	return false
}
