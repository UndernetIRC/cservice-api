// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package checks

import (
	"context"
	"errors"
	"testing"
	"time"

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
		assert.Equal(t, err, nil)
		assert.False(t, whitelisted)
	})

	t.Run("Return false on unknown error", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		db.On("GetWhiteListByIP", mock.Anything, ipv4).
			Return(models.Whitelist{}, errors.New("unknown error")).Once()
		InitIP(ctx, db)
		whitelisted, err := IP.IsWhitelisted(ipv4.IPNet.String())
		assert.Equal(t, err.Error(), "unknown error")
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

func TestIsGlined(t *testing.T) {
	ctx := context.Background()
	ipv4 := "192.168.1.1"
	ipv4Host := "*@192.168.1.0/24"
	integer := int32(1)
	reason := "test"

	t.Run("Return true if ipv4 is glined", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		db.On("GetGlineByIP", mock.Anything, "192.168.1.1").
			Return(models.Gline{
				ID:          &integer,
				Host:        ipv4Host,
				Addedby:     "test",
				Addedon:     int32(time.Now().Unix()),
				Expiresat:   int32(time.Now().Add(time.Hour).Unix()),
				Lastupdated: int32(time.Now().Unix()),
				Reason:      &reason,
			}, nil).Once()
		InitIP(ctx, db)
		glined, err := IP.IsGlined(ipv4)
		if err != nil {
			t.Fatal(err)
		}
		assert.True(t, glined)
	})

	t.Run("Return false if ipv4 is not whitelisted", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		db.On("GetGlineByIP", mock.Anything, ipv4).
			Return(models.Gline{}, pgx.ErrNoRows).Once()
		InitIP(ctx, db)
		whitelisted, err := IP.IsGlined(ipv4)
		assert.Equal(t, err, nil)
		assert.False(t, whitelisted)
	})

	t.Run("Return false on unknown error", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		db.On("GetGlineByIP", mock.Anything, ipv4).
			Return(models.Gline{}, errors.New("unknown error")).Once()
		InitIP(ctx, db)
		whitelisted, err := IP.IsGlined(ipv4)
		assert.Equal(t, err.Error(), "unknown error")
		assert.False(t, whitelisted)
	})

}
