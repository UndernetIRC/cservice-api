// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

// This file needs to be manually updated with the new models based on the file querier.go

// Package models contains the database models
package models

import (
	"github.com/jackc/pgx/v5"
)

// ServiceInterface is an interface for the database model
type ServiceInterface interface {
	Querier
	WithTx(tx pgx.Tx) ServiceInterface
}

// Service is a wrapper around the database queries that embeds all Querier methods
type Service struct {
	*Queries
}

// NewService creates a new Service
func NewService(db *Queries) *Service {
	return &Service{Queries: db}
}

// WithTx returns a new Service instance that wraps the provided transaction
func (s *Service) WithTx(tx pgx.Tx) ServiceInterface {
	return &Service{
		Queries: s.Queries.WithTx(tx),
	}
}
