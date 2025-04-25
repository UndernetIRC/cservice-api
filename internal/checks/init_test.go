// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2024 UnderNET

package checks

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/undernetirc/cservice-api/models"
)

func TestInitChecksInitializesServices(t *testing.T) {
	// Create a test context
	ctx := context.Background()

	// Reset the global service variables to ensure clean test
	IP = nil
	User = nil

	// Create a minimal test implementation of a Service
	// This is just for testing, not for actual use, since we're not testing functionality
	svc := &models.Service{}

	// Call the function under test
	InitChecks(ctx, svc)

	// Verify both services were initialized
	assert.NotNil(t, IP, "IP service should be initialized after calling InitChecks")
	assert.NotNil(t, User, "User service should be initialized after calling InitChecks")
}
