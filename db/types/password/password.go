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
