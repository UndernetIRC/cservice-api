# Development Guide

This guide covers development setup, testing, architecture, and troubleshooting for the Channel Services API.

## Table of Contents

- [Development Setup](#development-setup)
- [Database Development](#database-development)
- [Running the Service](#running-the-service)
- [Testing](#testing)
- [Architecture](#architecture)
- [Troubleshooting](#troubleshooting)

## Development Setup

### Prerequisites

1. Install Go 1.22 or newer
2. Install PostgreSQL 11.0 or newer
3. Install Valkey (Redis)
4. Install required Go tools:

```bash
go install github.com/golang-migrate/migrate/v4/cmd/migrate@latest
go install github.com/sqlc-dev/sqlc/cmd/sqlc@v1.28.0
go install github.com/air-verse/air@latest
```

### Database Setup

1. Setup PostgreSQL and create a database.

2. Run migrations:

```bash
DB_URL="postgres://cservice:cservice@localhost:5432/cservice?sslmode=disable" make migrate
```

Alternatively, prepare the configuration YAML file, and run:

```bash
bin/cservice-api -config </path/to/config.yaml>
```

## Database Development

This project uses [sqlc](https://docs.sqlc.dev/en/stable/) to generate Go code from SQL queries.

### Creating New Migrations

The database schema is defined in `db/migrations/*.sql`. Do _NOT_ modify existing migration files if a schema change is
necessary. Instead, create new migration files:

```bash
migrate create -ext sql -dir db/migrations <migration_name>
```

This will create two new migration files in `db/migrations` with the current timestamp for migrating up and down.
Edit these files to add your SQL statements.

### Generating Database Code

To generate the Go code from the migrations and SQL queries:

```bash
make generate-sqlc
```

After generating the code, you may need to update the `service.go` file in `models` to match the interface defined in
`models/querier.go`.

### Generating Test Mocks

After changing SQL queries or schema, update the database mocks for unit tests:

```bash
make generate-mocks
```

## Running the Service

### Development Mode with Live Reload

```bash
make watch
```

### Production Mode

```bash
make build
bin/cservice-api -config </path/to/config.yml>
```

## Testing

### Unit Tests

```bash
# Run all unit tests
make test

# Run tests with coverage
make test-coverage

# Run tests for specific package
go test ./controllers/...
go test ./internal/auth/...

# Run tests with verbose output
go test -v ./...

# Run only short tests (skip integration tests)
go test -short ./...
```

### Integration Tests

```bash
# Run integration tests (requires database)
make integration-test

# Run specific integration test
go test -run TestUserRegistration ./integration/

# Run integration tests with coverage
go test -coverprofile=integration.out ./integration/
```

### Test Coverage

```bash
# Generate coverage report
make test-coverage

# View coverage in browser
go tool cover -html=coverage.out

# Check coverage percentage
go tool cover -func=coverage.out | grep total
```

### Linting and Code Quality

```bash
# Run linter
make lint

# Fix automatically fixable issues
golangci-lint run --fix

# Run security checker
gosec ./...

# Check for outdated dependencies
go list -u -m all
```

### Testing Best Practices

- **Unit Tests**: Test business logic in isolation using mocks
- **Integration Tests**: Test complete workflows with real database
- **Table-Driven Tests**: Use table-driven tests for multiple scenarios
- **Test Fixtures**: Use consistent test data and database states
- **Parallel Testing**: Run tests in parallel where possible

### Example Test Structure

```go
func TestUserRegistration(t *testing.T) {
    tests := []struct {
        name           string
        input          RegisterRequest
        expectedStatus int
        expectedError  string
    }{
        {
            name: "valid registration",
            input: RegisterRequest{
                Username: "testuser",
                Email:    "test@example.com",
                Password: "SecurePassword123!",
            },
            expectedStatus: http.StatusCreated,
        },
        {
            name: "invalid email",
            input: RegisterRequest{
                Username: "testuser",
                Email:    "invalid-email",
                Password: "SecurePassword123!",
            },
            expectedStatus: http.StatusBadRequest,
            expectedError:  "invalid email format",
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Test implementation
        })
    }
}
```

## Architecture

### System Overview

The Channel Services API follows a clean architecture pattern with clear separation of concerns:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Controllers   │───▶│    Services     │───▶│    Database     │
│  (HTTP Layer)   │    │ (Business Logic)│    │   (PostgreSQL)  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Middlewares   │    │     Models      │    │     Cache       │
│ (Auth, Metrics) │    │ (Data Objects)  │    │    (Valkey)     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Key Components

#### Controllers (`/controllers`)
- Handle HTTP requests and responses
- Input validation and sanitization
- JWT token extraction and validation
- Error handling and logging

#### Services (`/models`)
- Business logic implementation
- Database query execution
- Transaction management
- Data transformation

#### Middlewares (`/middlewares`)
- Authentication and authorization
- Request logging and metrics
- Rate limiting
- CORS handling
- Request tracing

#### Internal Packages (`/internal`)
- **auth**: Authentication helpers (JWT, TOTP, password hashing)
- **config**: Configuration management
- **helper**: Utility functions and validators
- **mail**: Email sending and templating
- **metrics**: Application metrics and monitoring
- **telemetry**: OpenTelemetry integration

### Database Design

The system uses PostgreSQL with the following key tables:

- **users**: User accounts and authentication data
- **channels**: Registered IRC channels
- **pending**: Pending channel registrations
- **user_roles**: Role-based access control
- **noreg**: User registration restrictions
- **password_reset_tokens**: Temporary password reset tokens

### Security Architecture

- **JWT Authentication**: RSA-signed tokens with public key verification
- **Role-Based Access**: Multi-level administrative permissions
- **Input Validation**: Comprehensive sanitization and validation
- **SQL Injection Protection**: Parameterized queries via sqlc
- **Rate Limiting**: Per-user and per-endpoint rate limiting
- **Audit Logging**: Comprehensive logging of security events

## Troubleshooting

### Common Issues

#### Database Connection Issues

**Problem**: `connection refused` or `database does not exist`

```bash
# Check PostgreSQL is running
docker-compose ps db

# Check database logs
docker-compose logs db

# Recreate database volume if corrupted
docker-compose down -v
docker-compose up -d db

# Run migrations manually
DB_URL="postgres://cservice:cservice@localhost:5432/cservice?sslmode=disable" make migrate
```

#### JWT Authentication Errors

**Problem**: `invalid token` or `token has expired`

```bash
# Check JWT key files exist and have correct permissions
ls -la *.key *.pub

# Regenerate JWT keys if corrupted
openssl genrsa -out access_jwt.key 4096
openssl rsa -in access_jwt.key -pubout -out access_jwt.pub

# Verify configuration points to correct key files
grep -E "jwt|key" config.yml
```

#### Build/Compilation Issues

**Problem**: `module not found` or `build failed`

```bash
# Clean module cache
go clean -modcache

# Download dependencies
go mod download

# Regenerate code if needed
make generate-sqlc
make generate-mocks

# Full clean rebuild
make clean
make build
```

#### Testing Issues

**Problem**: Tests failing or database connection issues

```bash
# Ensure test database is available
export TEST_DB_URL="postgres://cservice:cservice@localhost:5432/cservice_test?sslmode=disable"

# Run only unit tests (no database required)
go test -short ./...

# Run with verbose output for debugging
go test -v ./controllers/...

# Generate test coverage report
make test-coverage
```

#### Docker Issues

**Problem**: Services not starting or port conflicts

```bash
# Check for port conflicts
lsof -i :8080 -i :5432 -i :6379

# Rebuild containers
docker-compose down
docker-compose build --no-cache
docker-compose up -d

# Check service health
docker-compose ps
docker-compose logs api
```

### Performance Issues

#### High Memory Usage

- Check for database connection leaks
- Monitor goroutine counts: `curl http://localhost:8080/debug/pprof/goroutine?debug=1`
- Profile memory usage: `go tool pprof http://localhost:8080/debug/pprof/heap`

#### Slow Database Queries

- Enable PostgreSQL query logging
- Check database indexes: `EXPLAIN ANALYZE SELECT ...`
- Monitor connection pool usage
- Consider query optimization in `db/queries/`

### Logging and Debugging

#### Application Logs

```bash
# Follow application logs
docker-compose logs -f api

# Filter by log level
docker-compose logs api | grep ERROR

# Enable debug logging
export CSERVICE_LOG_LEVEL=debug
```

#### Database Query Debugging

```bash
# Enable PostgreSQL query logging in docker-compose.yml
services:
  db:
    command: |
      postgres
      -c log_statement=all
      -c log_destination=stderr
      -c logging_collector=on
```

### Getting Help

- **Issues**: Report bugs on [GitHub Issues](https://github.com/UndernetIRC/cservice-api/issues)
- **Documentation**: Check `/docs` folder for detailed guides
- **API Docs**: Interactive documentation at `/docs` endpoint
- **Logs**: Always include relevant log output when reporting issues
