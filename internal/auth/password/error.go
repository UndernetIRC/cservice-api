// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

// Package password provides password hashing and validation.
package password

import "errors"

// ErrMismatchedHashAndPassword is returned when the password hash and password do not match.
var ErrMismatchedHashAndPassword = errors.New("mismatched password hash and password")

// ErrUnknownHashAlgorithm is returned when the hash algorithm is unknown.
var ErrUnknownHashAlgorithm = errors.New("unknown hash algorithm")
