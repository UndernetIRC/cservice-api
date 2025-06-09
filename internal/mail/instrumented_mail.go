// llSPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package mail

import (
	"context"
	"log"
	"sync/atomic"

	"github.com/undernetirc/cservice-api/internal/metrics"
)

// InstrumentedMailService wraps the mail functionality with metrics collection
type InstrumentedMailService struct {
	systemMetrics *metrics.SystemHealthMetrics
	workerCount   int64 // atomic counter for active workers
}

// NewInstrumentedMailService creates a new instrumented mail service
func NewInstrumentedMailService(systemMetrics *metrics.SystemHealthMetrics) *InstrumentedMailService {
	return &InstrumentedMailService{
		systemMetrics: systemMetrics,
		workerCount:   0,
	}
}

// GetMailQueueDepth returns the current depth of the mail queue
func (ims *InstrumentedMailService) GetMailQueueDepth() int64 {
	if MailQueue == nil {
		return 0
	}
	return int64(len(MailQueue))
}

// GetWorkerCount returns the current number of active mail workers
func (ims *InstrumentedMailService) GetWorkerCount() int64 {
	return atomic.LoadInt64(&ims.workerCount)
}

// ProcessMailWithMetrics wraps ProcessMail with metrics collection
func (ims *InstrumentedMailService) ProcessMailWithMetrics(ctx context.Context, mailData Mail) error {
	if ims.systemMetrics == nil {
		// Fallback to original function if no metrics
		return ProcessMail(mailData)
	}

	return ims.systemMetrics.MeasureMailProcessing(ctx, mailData.To, func() error {
		return ProcessMail(mailData)
	})
}

// InstrumentedMailWorker is an instrumented version of MailWorker that tracks metrics
func (ims *InstrumentedMailService) InstrumentedMailWorker(mailQueue chan Mail, mailErr chan error, workerCount int) {
	for x := 0; x < workerCount; x++ {
		go func(workerID int) {
			// Increment worker count
			atomic.AddInt64(&ims.workerCount, 1)
			defer atomic.AddInt64(&ims.workerCount, -1)

			log.Printf("Instrumented mail worker %d started", workerID)

			for m := range mailQueue {
				log.Printf("Instrumented mail worker %d processing email to %s", workerID, m.To)

				ctx := context.Background()
				err := ims.ProcessMailWithMetrics(ctx, m)

				if err != nil {
					log.Printf("Instrumented mail worker %d failed to process email to %s: %v", workerID, m.To, err)
					if mailErr != nil {
						mailErr <- err
					}
				} else {
					log.Printf("Instrumented mail worker %d successfully sent email to %s", workerID, m.To)
				}
			}
			log.Printf("Instrumented mail worker %d stopped", workerID)
		}(x)
	}
}

// StartInstrumentedMailWorkers starts the instrumented mail workers
// This is a drop-in replacement for the original MailWorker function
func (ims *InstrumentedMailService) StartInstrumentedMailWorkers(mailQueue chan Mail, mailErr chan error, workerCount int) {
	ims.InstrumentedMailWorker(mailQueue, mailErr, workerCount)
}

// GetSystemHealthCallbacks returns callback functions for system health metrics
func (ims *InstrumentedMailService) GetSystemHealthCallbacks() (
	getMailQueueDepth func() int64,
	getWorkerCount func() int64,
) {
	return ims.GetMailQueueDepth, ims.GetWorkerCount
}

// GetSystemStatus returns the overall mail system health status
// Returns 1 if healthy, 0 if unhealthy
func (ims *InstrumentedMailService) GetSystemStatus() int64 {
	// Check if mail queue is initialized
	if MailQueue == nil {
		return 0 // Unhealthy - mail queue not initialized
	}

	// Check if queue is severely backed up (more than 80% full)
	queueDepth := ims.GetMailQueueDepth()
	queueCapacity := int64(cap(MailQueue))

	if queueCapacity > 0 && queueDepth > (queueCapacity*8/10) {
		return 0 // Unhealthy - queue is severely backed up
	}

	// Check if we have active workers
	if ims.GetWorkerCount() == 0 {
		return 0 // Unhealthy - no active workers
	}

	return 1 // Healthy
}
