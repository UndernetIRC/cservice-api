//go:build integration

// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package integration

import (
	"context"
	"fmt"
	"log"
	"os"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/undernetirc/cservice-api/models"
)

var (
	dbPool *pgxpool.Pool
	db     *models.Queries
	rdb    *redis.Client
	ctx    context.Context
)

func TestMain(m *testing.M) {
	var err error
	ctx = context.Background()
	req := testcontainers.ContainerRequest{
		Image:        "valkey/valkey:7.2-alpine",
		ExposedPorts: []string{"6379"},
		WaitingFor:   wait.ForLog("Ready to accept connections"),
	}
	redisContainer, err := testcontainers.GenericContainer(
		ctx,
		testcontainers.GenericContainerRequest{
			ContainerRequest: req,
			Started:          true,
		},
	)
	redisEndpoint, err := redisContainer.Endpoint(ctx, "")
	if err != nil {
		log.Fatalf("error starting redis container: %s", err)
	}

	rdb = redis.NewClient(&redis.Options{
		Addr: redisEndpoint,
	})

	// Clean up the container
	defer func() {
		if err := redisContainer.Terminate(ctx); err != nil {
			log.Fatalf("failed to terminate container: %s", err)
		}
	}()

	dbName := "cservice-test"
	dbUser := "cservice-test"
	dbPassword := "cservice-test"

	postgresContainer, err := postgres.RunContainer(ctx,
		testcontainers.WithImage("postgres:15-alpine"),
		postgres.WithDatabase(dbName),
		postgres.WithUsername(dbUser),
		postgres.WithPassword(dbPassword),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(5*time.Second)),
	)
	if err != nil {
		log.Fatalf("failed to start container: %s", err)
	}

	// Clean up the container
	defer func() {
		if err := postgresContainer.Terminate(ctx); err != nil {
			log.Fatalf("failed to terminate container: %s", err)
		}
	}()

	dbUrl, err := postgresContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		log.Fatalf("failed to get connection string: %s", err)
	}
	dbPool, err = pgxpool.New(ctx, dbUrl)
	if err != nil {
		log.Fatalf("%s", err)
	}
	db = models.New(dbPool)

	// Run SQL migration
	sqlm, err := migrate.New("file://../db/migrations", dbUrl)
	if err != nil {
		fmt.Printf("Could not connecto to database: %s", err)
	}
	if err := sqlm.Up(); err != nil {
		fmt.Printf("Could not run migration: %s", err)
	}

	// Run tests
	code := m.Run()

	os.Exit(code)
}
