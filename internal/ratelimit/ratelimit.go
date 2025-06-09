// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023-2025 UnderNET

// Package ratelimit provides rate limiting functionality using Redis
package ratelimit

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// RateLimiter defines the interface for rate limiting
type RateLimiter interface {
	// Allow checks if a request is allowed for the given key
	// Returns true if allowed, false if rate limited, and the retry-after duration
	Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, time.Duration, error)
}

// RedisRateLimiter implements rate limiting using Redis sorted sets
type RedisRateLimiter struct {
	client *redis.Client
}

// NewRedisRateLimiter creates a new Redis-based rate limiter
func NewRedisRateLimiter(client *redis.Client) RateLimiter {
	return &RedisRateLimiter{
		client: client,
	}
}

// Allow implements the RateLimiter interface using a sliding window algorithm
func (r *RedisRateLimiter) Allow(
	ctx context.Context,
	key string,
	limit int,
	window time.Duration,
) (bool, time.Duration, error) {
	now := time.Now()
	windowStart := now.Add(-window)
	windowKey := fmt.Sprintf("ratelimit:%s", key)

	// Use Redis pipeline for atomic operations
	pipe := r.client.Pipeline()

	// Remove expired entries (older than window)
	pipe.ZRemRangeByScore(ctx, windowKey, "0", fmt.Sprintf("%d", windowStart.UnixNano()))

	pipe.ZCard(ctx, windowKey)

	pipe.ZAdd(ctx, windowKey, redis.Z{
		Score:  float64(now.UnixNano()),
		Member: now.UnixNano(),
	})

	pipe.Expire(ctx, windowKey, window+time.Minute)

	results, err := pipe.Exec(ctx)
	if err != nil {
		return false, 0, fmt.Errorf("rate limiter pipeline error: %w", err)
	}

	countCmd, ok := results[1].(*redis.IntCmd)
	if !ok {
		return false, 0, fmt.Errorf("unexpected Redis command result type")
	}

	currentCount := countCmd.Val()

	if currentCount >= int64(limit) {
		r.client.ZRem(ctx, windowKey, now.UnixNano())

		retryAfter := r.calculateRetryAfter(ctx, windowKey, window)
		return false, retryAfter, nil
	}

	return true, 0, nil
}

// calculateRetryAfter determines when the client can retry
func (r *RedisRateLimiter) calculateRetryAfter(
	ctx context.Context,
	windowKey string,
	window time.Duration,
) time.Duration {
	oldestCmd := r.client.ZRange(ctx, windowKey, 0, 0)
	oldest, err := oldestCmd.Result()
	if err != nil || len(oldest) == 0 {
		return window
	}

	oldestTime, err := strconv.ParseInt(oldest[0], 10, 64)
	if err != nil {
		return window
	}

	oldestTimestamp := time.Unix(0, oldestTime)
	retryAfter := time.Until(oldestTimestamp.Add(window))

	if retryAfter < time.Second {
		retryAfter = time.Second
	}

	return retryAfter
}
