// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

// Package checks contains functions intended for Is, Has, etc. checks
package checks

import (
	"context"
	"net/netip"

	"github.com/jackc/pgx/v5"

	"github.com/undernetirc/cservice-api/models"
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
	ipAddr, err := netip.ParseAddr(ip)
	if err != nil {
		return false, err
	}

	_, err = i.s.GetWhiteListByIP(i.c, ipAddr)
	if err == pgx.ErrNoRows {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, nil
}

// IsGlined checks if an IP is g-lined
// Returns true if the IP is g-lined, false if not, and an error if there was an issue
func (i *IPService) IsGlined(ip string) (bool, error) {
	_, err := i.s.GetGlineByIP(i.c, ip)
	if err == pgx.ErrNoRows {
		return false, nil
	} else if err != nil {
		return false, err
	}

	return true, nil
}
