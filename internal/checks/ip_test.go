// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package checks

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v4"

	"github.com/stretchr/testify/mock"

	"github.com/stretchr/testify/assert"

	"github.com/jackc/pgtype"
	"github.com/undernetirc/cservice-api/db/mocks"
	"github.com/undernetirc/cservice-api/models"
)

func TestIsWhitelisted(t *testing.T) {
	ctx := context.Background()
	var ipv4 pgtype.Inet
	var ipv6 pgtype.Inet
	if err := ipv4.Set("192.168.1.1"); err != nil {
		t.Fatal(err)
	}
	if err := ipv6.Set("2001:2002:10::1"); err != nil {
		t.Fatal(err)
	}

	integer := int32(1)
	reason := "test"

	t.Run("Return true if ipv4 is whitelisted", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		db.On("GetWhiteListByIP", mock.Anything, ipv4).
			Return(models.Whitelist{
				ID:        &integer,
				Ip:        ipv4,
				Addedby:   "",
				Addedon:   0,
				Expiresat: 0,
				Reason:    &reason,
			}, nil).Once()
		InitIP(ctx, db)
		whitelisted, err := IP.IsWhitelisted(ipv4.IPNet.String())
		if err != nil {
			t.Fatal(err)
		}
		assert.True(t, whitelisted)
	})

	t.Run("Return true if ipv6 is whitelisted", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		db.On("GetWhiteListByIP", mock.Anything, ipv6).
			Return(models.Whitelist{
				ID:        &integer,
				Ip:        ipv4,
				Addedby:   "",
				Addedon:   0,
				Expiresat: 0,
				Reason:    &reason,
			}, nil).Once()
		InitIP(ctx, db)
		whitelisted, err := IP.IsWhitelisted(ipv6.IPNet.String())
		if err != nil {
			t.Fatal(err)
		}
		assert.True(t, whitelisted)
	})

	t.Run("Return false if ipv4 is not whitelisted", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		db.On("GetWhiteListByIP", mock.Anything, ipv4).
			Return(models.Whitelist{}, pgx.ErrNoRows).Once()
		InitIP(ctx, db)
		whitelisted, err := IP.IsWhitelisted(ipv4.IPNet.String())
		if err != nil {
			assert.Equal(t, err, pgx.ErrNoRows)
		}
		assert.False(t, whitelisted)
	})

	t.Run("Return error on invalid ip", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		InitIP(ctx, db)
		whitelisted, err := IP.IsWhitelisted("x.x.x.x")
		if err != nil {
			assert.Contains(t, err.Error(), "unable to parse inet")
		}
		assert.False(t, whitelisted)
	})

}