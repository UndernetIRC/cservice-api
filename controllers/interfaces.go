// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package controllers

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// PoolInterface defines the interface for database pool operations
type PoolInterface interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}
