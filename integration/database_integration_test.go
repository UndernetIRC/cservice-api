//go:build integration

// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2024 UnderNET

package integration

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/undernetirc/cservice-api/db/types/flags"
	"github.com/undernetirc/cservice-api/db/types/password"
	"github.com/undernetirc/cservice-api/models"
)

// TestDatabaseIntegration exercises the sqlc-generated queries against the
// real Postgres provisioned by main_test.go's testcontainers setup.
func TestDatabaseIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration tests in short mode")
	}

	t.Run("User Operations", func(t *testing.T) {
		testUserOperations(t)
	})

	t.Run("Channel Operations", func(t *testing.T) {
		testChannelOperations(t)
	})

	t.Run("Channel Membership Operations", func(t *testing.T) {
		testChannelMembershipOperations(t)
	})

	t.Run("Complex Queries", func(t *testing.T) {
		testComplexQueries(t)
	})
}

func testUserOperations(t *testing.T) {
	ctx := context.Background()

	// Fresh user per run to avoid uniqueness conflicts.
	suffix := strconv.FormatInt(time.Now().UnixNano()%1000000, 10)
	createParams := models.CreateUserParams{
		Username:         "itst_" + suffix,
		Password:         password.Password("hashed_password"),
		Email:            pgtype.Text{String: "itst_" + suffix + "@test.com", Valid: true},
		Flags:            0,
		LastUpdated:      int32(time.Now().Unix()),
		LastUpdatedBy:    pgtype.Text{String: "test", Valid: true},
		LanguageID:       pgtype.Int4{Int32: 1, Valid: true},
		QuestionID:       pgtype.Int2{Int16: 1, Valid: true},
		Verificationdata: pgtype.Text{String: "test_data", Valid: true},
		SignupTs:         pgtype.Int4{Int32: int32(time.Now().Unix()), Valid: true},
	}

	user, err := db.CreateUser(ctx, createParams)
	require.NoError(t, err)
	assert.NotZero(t, user.ID)
	assert.Equal(t, createParams.Username, user.Username)
	assert.Equal(t, createParams.Email.String, user.Email.String)

	retrievedUser, err := db.GetUser(ctx, models.GetUserParams{ID: user.ID})
	require.NoError(t, err)
	assert.Equal(t, user.ID, retrievedUser.ID)
	assert.Equal(t, user.Username, retrievedUser.Username)

	userByUsername, err := db.GetUser(ctx, models.GetUserParams{Username: user.Username})
	require.NoError(t, err)
	assert.Equal(t, user.ID, userByUsername.ID)

	err = db.UpdateUserFlags(ctx, models.UpdateUserFlagsParams{
		ID:    user.ID,
		Flags: flags.UserTotpEnabled,
	})
	require.NoError(t, err)

	updatedUser, err := db.GetUser(ctx, models.GetUserParams{ID: user.ID})
	require.NoError(t, err)
	assert.True(t, updatedUser.Flags.HasFlag(flags.UserTotpEnabled))
}

func testChannelOperations(t *testing.T) {
	ctx := context.Background()

	// Rely on the seed data provided by the migration fixtures.
	channelID := int32(1)
	channel, err := db.GetChannelByID(ctx, channelID)
	if err != nil {
		t.Skip("No seeded channel with ID 1 available")
		return
	}

	assert.NotZero(t, channel.ID)
	assert.NotEmpty(t, channel.Name)

	channelByName, err := db.GetChannelByName(ctx, channel.Name)
	require.NoError(t, err)
	assert.Equal(t, channel.ID, channelByName.ID)

	searchResult, err := db.SearchChannels(ctx, models.SearchChannelsParams{
		Name:   "%" + channel.Name + "%",
		Limit:  10,
		Offset: 0,
	})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(searchResult), 1)

	existsResult, err := db.CheckChannelExists(ctx, channel.ID)
	require.NoError(t, err)
	assert.Equal(t, channel.ID, existsResult.ID)
}

func testChannelMembershipOperations(t *testing.T) {
	ctx := context.Background()

	userID := int32(1)
	channelID := int32(1)

	memberData, err := db.CheckChannelMemberExists(ctx, channelID, userID)
	if err != nil {
		t.Skip("No seeded membership for user 1 / channel 1 available")
		return
	}

	access, err := db.GetChannelUserAccess(ctx, channelID, userID)
	if err == nil {
		assert.NotZero(t, access.Access)
	}

	if memberData.ChannelID == 0 {
		_, err = db.AddChannelMember(ctx, models.AddChannelMemberParams{
			ChannelID: channelID,
			UserID:    userID,
			Access:    500,
			AddedBy:   pgtype.Text{String: "system", Valid: true},
		})
		require.NoError(t, err)

		newMemberData, err := db.CheckChannelMemberExists(ctx, channelID, userID)
		require.NoError(t, err)
		assert.NotZero(t, newMemberData.ChannelID)
	}

	members, err := db.GetChannelMembersByAccessLevel(ctx, channelID, 500)
	require.NoError(t, err)
	t.Logf("Found %d members with access level 500", len(members))

	ownerCount, err := db.CountChannelOwners(ctx, channelID)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, ownerCount, int64(0))
}

func testComplexQueries(t *testing.T) {
	ctx := context.Background()

	userID := int32(1)
	memberships, err := db.GetUserChannelMemberships(ctx, userID)
	if err != nil {
		t.Skip("No user membership data available for user 1")
		return
	}

	t.Logf("User %d has %d channel memberships", userID, len(memberships))

	channels, err := db.GetUserChannels(ctx, userID)
	require.NoError(t, err)
	t.Logf("User %d is in %d channels", userID, len(channels))

	if _, err := db.GetAdminLevel(ctx, userID); err == nil {
		t.Logf("User %d has an admin-level row", userID)
	}

	if len(channels) > 0 {
		details, err := db.GetChannelDetails(ctx, channels[0].ChannelID)
		require.NoError(t, err)
		assert.NotZero(t, details.ID)
		assert.NotEmpty(t, details.Name)
	}
}

func BenchmarkChannelSearch(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping benchmark in short mode")
	}

	ctx := context.Background()
	searchParams := models.SearchChannelsParams{
		Name:   "%test%",
		Limit:  20,
		Offset: 0,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := db.SearchChannels(ctx, searchParams); err != nil {
			b.Fatalf("Search failed: %v", err)
		}
	}
}

func BenchmarkUserChannelMemberships(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping benchmark in short mode")
	}

	ctx := context.Background()
	userID := int32(1)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := db.GetUserChannelMemberships(ctx, userID); err != nil {
			b.Fatalf("Query failed: %v", err)
		}
	}
}
