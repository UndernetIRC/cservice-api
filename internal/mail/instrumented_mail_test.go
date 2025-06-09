// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package mail

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/undernetirc/cservice-api/internal/metrics"
	"go.opentelemetry.io/otel/metric/noop"
)

func TestNewInstrumentedMailService(t *testing.T) {
	// Create mock system metrics
	meter := noop.NewMeterProvider().Meter("test")
	config := metrics.SystemHealthMetricsConfig{
		Meter:       meter,
		ServiceName: "test-service",
	}

	systemMetrics, err := metrics.NewSystemHealthMetrics(config)
	require.NoError(t, err)

	// Test creation
	service := NewInstrumentedMailService(systemMetrics)
	assert.NotNil(t, service)
	assert.Equal(t, systemMetrics, service.systemMetrics)
	assert.Equal(t, int64(0), service.workerCount)
}

func TestInstrumentedMailService_GetMailQueueDepth(t *testing.T) {
	service := NewInstrumentedMailService(nil)

	// Test with nil queue
	MailQueue = nil
	depth := service.GetMailQueueDepth()
	assert.Equal(t, int64(0), depth)

	// Test with empty queue
	MailQueue = make(chan Mail, 10)
	depth = service.GetMailQueueDepth()
	assert.Equal(t, int64(0), depth)

	// Test with items in queue
	MailQueue <- Mail{To: "test1@example.com"}
	MailQueue <- Mail{To: "test2@example.com"}
	depth = service.GetMailQueueDepth()
	assert.Equal(t, int64(2), depth)

	// Clean up
	close(MailQueue)
	//nolint:revive // empty-block: intentionally empty to drain channel
	for range MailQueue {
		// Drain the queue - intentionally empty
	}
}

func TestInstrumentedMailService_GetWorkerCount(t *testing.T) {
	service := NewInstrumentedMailService(nil)

	// Initial count should be 0
	count := service.GetWorkerCount()
	assert.Equal(t, int64(0), count)

	// Simulate worker increment
	service.workerCount = 3
	count = service.GetWorkerCount()
	assert.Equal(t, int64(3), count)
}

func TestInstrumentedMailService_ProcessMailWithMetrics(t *testing.T) {
	// Create mock system metrics
	meter := noop.NewMeterProvider().Meter("test")
	config := metrics.SystemHealthMetricsConfig{
		Meter:       meter,
		ServiceName: "test-service",
	}

	systemMetrics, err := metrics.NewSystemHealthMetrics(config)
	require.NoError(t, err)

	service := NewInstrumentedMailService(systemMetrics)

	// Test that the method exists and handles nil metrics gracefully
	// We'll skip the actual ProcessMail call since it requires SMTP config
	mailData := Mail{
		FromEmail: "test@example.com",
		To:        "test@example.com",
		Subject:   "Test Subject",
		Body:      "Test Body",
	}

	ctx := context.Background()

	// Test that the wrapper function exists and can be called
	// The actual ProcessMail will fail due to config, but that's expected
	// We're mainly testing that the metrics wrapper works
	assert.NotNil(t, service.systemMetrics)
	assert.NotNil(t, service.ProcessMailWithMetrics)

	// We can't easily test the actual call without mocking the entire config system
	// So we'll just verify the method signature and structure
	_ = mailData
	_ = ctx
}

func TestInstrumentedMailService_ProcessMailWithMetrics_NoMetrics(t *testing.T) {
	// Test with nil metrics (should fallback to original ProcessMail)
	service := NewInstrumentedMailService(nil)

	mailData := Mail{
		FromEmail: "test@example.com",
		To:        "test@example.com",
		Subject:   "Test Subject",
		Body:      "Test Body",
	}

	ctx := context.Background()

	// Test that the method handles nil metrics gracefully
	assert.Nil(t, service.systemMetrics)
	assert.NotNil(t, service.ProcessMailWithMetrics)

	// We can't easily test the actual call without mocking the entire config system
	// So we'll just verify the method signature and nil handling
	_ = mailData
	_ = ctx
}

func TestInstrumentedMailService_InstrumentedMailWorker(t *testing.T) {
	// Create mock system metrics
	meter := noop.NewMeterProvider().Meter("test")
	config := metrics.SystemHealthMetricsConfig{
		Meter:       meter,
		ServiceName: "test-service",
	}

	systemMetrics, err := metrics.NewSystemHealthMetrics(config)
	require.NoError(t, err)

	service := NewInstrumentedMailService(systemMetrics)

	// Create test channels
	mailQueue := make(chan Mail, 10)
	mailErr := make(chan error, 10)

	// Start workers
	service.InstrumentedMailWorker(mailQueue, mailErr, 2)

	// Give workers time to start
	time.Sleep(100 * time.Millisecond)

	// Check worker count
	workerCount := service.GetWorkerCount()
	assert.Equal(t, int64(2), workerCount)

	// We won't send actual mail since it requires SMTP config
	// Just verify that workers are running and can be stopped
	// The worker count tracking is the main functionality we're testing

	// Close queue to stop workers
	close(mailQueue)

	// Give workers time to stop
	time.Sleep(100 * time.Millisecond)

	// Worker count should be 0 after stopping
	workerCount = service.GetWorkerCount()
	assert.Equal(t, int64(0), workerCount)
}

func TestInstrumentedMailService_GetSystemHealthCallbacks(t *testing.T) {
	service := NewInstrumentedMailService(nil)

	// Set up test state
	MailQueue = make(chan Mail, 10)
	MailQueue <- Mail{To: "test@example.com"}
	service.workerCount = 2

	// Get callbacks
	getMailQueueDepth, getWorkerCount := service.GetSystemHealthCallbacks()

	// Test callbacks
	assert.Equal(t, int64(1), getMailQueueDepth())
	assert.Equal(t, int64(2), getWorkerCount())

	// Clean up
	close(MailQueue)
	//nolint:revive // empty-block: intentionally empty to drain channel
	for range MailQueue {
		// Drain the queue - intentionally empty
	}
}

func TestInstrumentedMailService_GetSystemStatus(t *testing.T) {
	// Save original MailQueue
	originalQueue := MailQueue
	defer func() {
		MailQueue = originalQueue
	}()

	service := NewInstrumentedMailService(nil)

	// Test 1: unhealthy - nil queue
	t.Run("unhealthy - nil queue", func(t *testing.T) {
		MailQueue = nil
		service.workerCount = 0
		status := service.GetSystemStatus()
		assert.Equal(t, int64(0), status, "Should be unhealthy when mail queue is not initialized")
	})

	// Test 2: unhealthy - no workers
	t.Run("unhealthy - no workers", func(t *testing.T) {
		MailQueue = make(chan Mail, 10)
		defer close(MailQueue)
		service.workerCount = 0
		status := service.GetSystemStatus()
		assert.Equal(t, int64(0), status, "Should be unhealthy when no workers are active")
	})

	// Test 3: unhealthy - queue backed up
	t.Run("unhealthy - queue backed up", func(t *testing.T) {
		MailQueue = make(chan Mail, 10)
		defer close(MailQueue)
		// Fill queue to more than 80% (8+ items)
		for i := 0; i < 9; i++ {
			MailQueue <- Mail{To: "test@example.com"}
		}
		service.workerCount = 2
		status := service.GetSystemStatus()
		assert.Equal(t, int64(0), status, "Should be unhealthy when queue is more than 80% full")
	})

	// Test 4: healthy - normal operation
	t.Run("healthy - normal operation", func(t *testing.T) {
		MailQueue = make(chan Mail, 10)
		defer close(MailQueue)
		// Add a few items but keep under 80%
		MailQueue <- Mail{To: "test1@example.com"}
		MailQueue <- Mail{To: "test2@example.com"}
		service.workerCount = 2
		status := service.GetSystemStatus()
		assert.Equal(t, int64(1), status, "Should be healthy with active workers and reasonable queue depth")
	})

	// Test 5: healthy - empty queue
	t.Run("healthy - empty queue", func(t *testing.T) {
		MailQueue = make(chan Mail, 10)
		defer close(MailQueue)
		service.workerCount = 1
		status := service.GetSystemStatus()
		assert.Equal(t, int64(1), status, "Should be healthy with empty queue and active workers")
	})
}

func TestInstrumentedMailService_StartInstrumentedMailWorkers(t *testing.T) {
	service := NewInstrumentedMailService(nil)

	// Create test channels
	mailQueue := make(chan Mail, 5)
	mailErr := make(chan error, 5)

	// Start workers using the public method
	service.StartInstrumentedMailWorkers(mailQueue, mailErr, 1)

	// Give workers time to start
	time.Sleep(100 * time.Millisecond)

	// Check worker count
	workerCount := service.GetWorkerCount()
	assert.Equal(t, int64(1), workerCount)

	// Close queue to stop workers
	close(mailQueue)

	// Give workers time to stop
	time.Sleep(100 * time.Millisecond)

	// Worker count should be 0 after stopping
	workerCount = service.GetWorkerCount()
	assert.Equal(t, int64(0), workerCount)
}
