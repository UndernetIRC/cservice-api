// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

// Package checks contains functions intended for Is, Has, etc. checks
package checks

import (
	"context"

	"github.com/undernetirc/cservice-api/models"
)

// InitChecks initializes all the utility checks that require access to the database
func InitChecks(ctx context.Context, s *models.Service) {
	InitIP(ctx, s)
	InitUser(ctx, s)
}
