// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023-2025 UnderNET

package ratelimit

import (
	"context"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestRedis(t *testing.T) *redis.Client {
	// Use a test database to avoid conflicts
	client := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
		DB:   15, // Use test database
	})

	// Test connection
	ctx := context.Background()
	err := client.Ping(ctx).Err()
	if err != nil {
		t.Skip("Redis not available for testing")
	}

	// Clean up any existing test data
	client.FlushDB(ctx)

	return client
}

func TestRedisRateLimiter_Allow(t *testing.T) {
	client := setupTestRedis(t)
	defer client.Close()

	limiter := NewRedisRateLimiter(client)
	ctx := context.Background()
	key := "test:user:123"
	limit := 3
	window := time.Minute

	// First 3 requests should be allowed
	for i := 0; i < limit; i++ {
		allowed, retryAfter, err := limiter.Allow(ctx, key, limit, window)
		require.NoError(t, err)
		assert.True(t, allowed, "Request %d should be allowed", i+1)
		assert.Zero(t, retryAfter, "No retry after for allowed requests")
	}

	// 4th request should be denied
	allowed, retryAfter, err := limiter.Allow(ctx, key, limit, window)
	require.NoError(t, err)
	assert.False(t, allowed, "4th request should be denied")
	assert.Greater(t, retryAfter, time.Duration(0), "Should have retry after duration")
	assert.LessOrEqual(t, retryAfter, window, "Retry after should not exceed window")
}

func TestRedisRateLimiter_SlidingWindow(t *testing.T) {
	client := setupTestRedis(t)
	defer client.Close()

	limiter := NewRedisRateLimiter(client)
	ctx := context.Background()
	key := "test:sliding:123"
	limit := 2
	window := 2 * time.Second

	// Make 2 requests (should be allowed)
	for i := 0; i < limit; i++ {
		allowed, _, err := limiter.Allow(ctx, key, limit, window)
		require.NoError(t, err)
		assert.True(t, allowed)
	}

	// 3rd request should be denied
	allowed, retryAfter, err := limiter.Allow(ctx, key, limit, window)
	require.NoError(t, err)
	assert.False(t, allowed)
	assert.Greater(t, retryAfter, time.Duration(0))

	// Wait for window to partially expire
	time.Sleep(1 * time.Second)

	// Should still be denied (sliding window)
	allowed, _, err = limiter.Allow(ctx, key, limit, window)
	require.NoError(t, err)
	assert.False(t, allowed)

	// Wait for full window to expire
	time.Sleep(2 * time.Second)

	// Should be allowed again
	allowed, _, err = limiter.Allow(ctx, key, limit, window)
	require.NoError(t, err)
	assert.True(t, allowed)
}

func TestRedisRateLimiter_DifferentKeys(t *testing.T) {
	client := setupTestRedis(t)
	defer client.Close()

	limiter := NewRedisRateLimiter(client)
	ctx := context.Background()
	limit := 1
	window := time.Minute

	// Different keys should have independent limits
	key1 := "test:user:123"
	key2 := "test:user:456"

	// Both should be allowed
	allowed1, _, err := limiter.Allow(ctx, key1, limit, window)
	require.NoError(t, err)
	assert.True(t, allowed1)

	allowed2, _, err := limiter.Allow(ctx, key2, limit, window)
	require.NoError(t, err)
	assert.True(t, allowed2)

	// Second request for each should be denied
	allowed1, _, err = limiter.Allow(ctx, key1, limit, window)
	require.NoError(t, err)
	assert.False(t, allowed1)

	allowed2, _, err = limiter.Allow(ctx, key2, limit, window)
	require.NoError(t, err)
	assert.False(t, allowed2)
}

func TestRedisRateLimiter_RetryAfterCalculation(t *testing.T) {
	client := setupTestRedis(t)
	defer client.Close()

	limiter := NewRedisRateLimiter(client)
	ctx := context.Background()
	key := "test:retry:123"
	limit := 1
	window := 5 * time.Second

	// First request allowed
	allowed, _, err := limiter.Allow(ctx, key, limit, window)
	require.NoError(t, err)
	assert.True(t, allowed)

	// Second request denied with retry after
	allowed, retryAfter, err := limiter.Allow(ctx, key, limit, window)
	require.NoError(t, err)
	assert.False(t, allowed)
	assert.Greater(t, retryAfter, time.Second, "Should have at least 1 second retry after")
	assert.LessOrEqual(t, retryAfter, window, "Retry after should not exceed window")
}

func TestRedisRateLimiter_ErrorHandling(t *testing.T) {
	// Create a client with invalid configuration to test error handling
	client := redis.NewClient(&redis.Options{
		Addr: "invalid:6379",
	})
	defer client.Close()

	limiter := NewRedisRateLimiter(client)
	ctx := context.Background()
	key := "test:error:123"
	limit := 1
	window := time.Minute

	// Should return error when Redis is unavailable
	allowed, retryAfter, err := limiter.Allow(ctx, key, limit, window)
	assert.Error(t, err)
	assert.False(t, allowed)
	assert.Zero(t, retryAfter)
}

func TestRedisRateLimiter_ContextCancellation(t *testing.T) {
	client := setupTestRedis(t)
	defer client.Close()

	limiter := NewRedisRateLimiter(client)
	key := "test:context:123"
	limit := 1
	window := time.Minute

	// Create a cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Should handle context cancellation
	allowed, retryAfter, err := limiter.Allow(ctx, key, limit, window)
	assert.Error(t, err)
	assert.False(t, allowed)
	assert.Zero(t, retryAfter)
}

func TestRedisRateLimiter_HighConcurrency(t *testing.T) {
	client := setupTestRedis(t)
	defer client.Close()

	limiter := NewRedisRateLimiter(client)
	ctx := context.Background()
	key := "test:concurrent:123"
	limit := 5
	window := time.Minute

	// Run concurrent requests
	results := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			allowed, _, err := limiter.Allow(ctx, key, limit, window)
			if err != nil {
				results <- false
				return
			}
			results <- allowed
		}()
	}

	// Collect results
	allowedCount := 0
	deniedCount := 0
	for i := 0; i < 10; i++ {
		if <-results {
			allowedCount++
		} else {
			deniedCount++
		}
	}

	// Should have exactly 'limit' allowed requests
	assert.Equal(t, limit, allowedCount, "Should allow exactly %d requests", limit)
	assert.Equal(t, 10-limit, deniedCount, "Should deny %d requests", 10-limit)
}

func TestRedisRateLimiter_KeyExpiration(t *testing.T) {
	client := setupTestRedis(t)
	defer client.Close()

	limiter := NewRedisRateLimiter(client)
	ctx := context.Background()
	key := "test:expiration:123"
	limit := 1
	window := 1 * time.Second

	// Make a request
	allowed, _, err := limiter.Allow(ctx, key, limit, window)
	require.NoError(t, err)
	assert.True(t, allowed)

	// Check that key exists
	windowKey := "ratelimit:" + key
	exists := client.Exists(ctx, windowKey).Val()
	assert.Equal(t, int64(1), exists, "Rate limit key should exist")

	// Check TTL is set (should be window + buffer = ~2 minutes)
	ttl := client.TTL(ctx, windowKey).Val()
	assert.Greater(t, ttl, time.Duration(0), "Key should have TTL set")
	assert.LessOrEqual(t, ttl, window+time.Minute, "TTL should not exceed window + buffer")

	// Wait for the sliding window to clear the entry
	time.Sleep(window + 100*time.Millisecond)

	// Make another request to trigger cleanup
	allowed, _, err = limiter.Allow(ctx, key, limit, window)
	require.NoError(t, err)
	assert.True(t, allowed, "Should be allowed after window expires")

	// The old entry should be cleaned up by the sliding window logic
	// Check the sorted set size - should only have the new entry
	count := client.ZCard(ctx, windowKey).Val()
	assert.Equal(t, int64(1), count, "Should only have one entry after cleanup")
}
