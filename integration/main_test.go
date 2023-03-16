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
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"github.com/redis/go-redis/v9"
	"github.com/undernetirc/cservice-api/models"
)

var (
	dbPool     *pgxpool.Pool
	db         *models.Queries
	rdb        *redis.Client
	ctx        context.Context
	dockerPool *dockertest.Pool
)

func TestMain(m *testing.M) {
	var err error
	ctx = context.Background()

	dockerPool, err = dockertest.NewPool("")
	if err != nil {
		log.Fatalf("Could not construct dockerPool: %s", err)
	}

	err = dockerPool.Client.Ping()
	if err != nil {
		log.Fatalf("Could not connect to docker: %s", err)
	}

	var postgresContainer, redisContainer *dockertest.Resource

	postgresContainer, err = startPostgres(dockerPool, "15-alpine")
	if err != nil {
		log.Fatalf("Could not start postgres: %s", err)
	}

	redisContainer, err = startRedis(dockerPool, "7-alpine")
	if err != nil {
		log.Fatalf("Could not start redis: %s", err)
	}

	//Run tests
	code := m.Run()

	// You can't defer this because os.Exit doesn't care for defer
	if err := dockerPool.Purge(postgresContainer); err != nil {
		log.Fatalf("Could not purge resource: %s", err)
	}

	if err := dockerPool.Purge(redisContainer); err != nil {
		log.Fatalf("Could not purge resource: %s", err)
	}

	os.Exit(code)
}

func startPostgres(pool *dockertest.Pool, postgresVersion string) (*dockertest.Resource, error) {
	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "postgres",
		Tag:        postgresVersion,
		Env: []string{
			"POSTGRES_USER=cservice-test",
			"POSTGRES_PASSWORD=cservice-test",
			"POSTGRES_DB=cservice-test",
			//"listen_addresses='*'",
		},
	}, func(config *docker.HostConfig) {
		// set AutoRemove to true so that stopped container goes away by itself
		config.AutoRemove = true
		config.RestartPolicy = docker.RestartPolicy{Name: "no"}
	})
	if err != nil {
		fmt.Printf("Could not start postgres: %s", err)
		return resource, err
	}

	hostAndPort := resource.GetHostPort("5432/tcp")
	dbUrl := fmt.Sprintf("postgres://cservice-test:cservice-test@%s/cservice-test?sslmode=disable", hostAndPort)

	resource.Expire(120) // Tell docker to hard kill the container in 120 seconds

	// exponential backoff-retry, because the application in the container might not be ready to accept connections yet
	pool.MaxWait = 30 * time.Second
	if err = pool.Retry(func() error {
		dbPool, err = pgxpool.Connect(ctx, dbUrl)
		if err != nil {
			return err
		}
		return dbPool.Ping(ctx)
	}); err != nil {
		fmt.Printf("Could not connect to docker: %s", err)
		return resource, err
	}
	db = models.New(dbPool)

	//Run SQL migration
	sqlm, err := migrate.New("file://../db/migrations", dbUrl)
	if err != nil {
		fmt.Printf("Could not connecto to database: %s", err)
		return resource, err
	}
	if err := sqlm.Up(); err != nil {
		fmt.Printf("Could not run migration: %s", err)
		return resource, err
	}
	return resource, nil
}

func startRedis(pool *dockertest.Pool, redisVersion string) (*dockertest.Resource, error) {
	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "redis",
		Tag:        redisVersion,
	}, func(config *docker.HostConfig) {
		// set AutoRemove to true so that stopped container goes away by itself
		config.AutoRemove = true
		config.RestartPolicy = docker.RestartPolicy{Name: "no"}
	})
	if err != nil {
		fmt.Printf("Could not start postgres: %s", err)
		return resource, err
	}

	hostAndPort := resource.GetHostPort("6379/tcp")
	resource.Expire(120) // Tell docker to hard kill the container in 120 seconds

	// exponential backoff-retry, because the application in the container might not be ready to accept connections yet
	pool.MaxWait = 30 * time.Second
	if err = pool.Retry(func() error {
		rdb = redis.NewClient(&redis.Options{
			Addr: hostAndPort,
		})
		if err := rdb.Ping(ctx).Err(); err != nil {
			return err
		}
		return nil
	}); err != nil {
		fmt.Printf("Could not connect to docker: %s", err)
		return resource, err
	}

	return resource, nil
}
