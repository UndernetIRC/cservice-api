// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

// Package checks contains functions intended for Is, Has, etc. checks
package checks

import (
	"context"

	"github.com/undernetirc/cservice-api/models"

	"github.com/jackc/pgtype"
)

// IP provides the IP service
var IP *IPService

// IPService is the IP service
type IPService struct {
	c context.Context
	s models.Querier
}

// InitIP initializes the IP service
func InitIP(c context.Context, s models.Querier) {
	IP = &IPService{
		c: c,
		s: s,
	}
}

// IsWhitelisted checks if an IP is whitelisted in the database
func (i *IPService) IsWhitelisted(ip string) (bool, error) {
	var ipParam pgtype.Inet
	if err := ipParam.Set(ip); err != nil {
		return false, err
	}

	_, err := i.s.GetWhiteListByIP(i.c, ipParam)
	if err != nil {
		return false, err
	}
	return true, nil
}
