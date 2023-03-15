// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package password

import (
	pass "github.com/undernetirc/cservice-api/internal/auth/password"
)

type Password string

func (p *Password) Validate(password string) error {
	v := pass.GetValidatorFunc(string(*p))
	return v(password)
}

func (p *Password) Set(password string) error {
	hash, err := pass.GenerateHash(pass.DefaultHasher, password)
	if err != nil {
		return err
	}
	*p = Password(hash)
	return nil
}
