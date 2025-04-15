[![CI](https://github.com/UndernetIRC/cservice-api/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/UndernetIRC/cservice-api/actions/workflows/ci.yml) [![Codacy Badge](https://app.codacy.com/project/badge/Grade/7399b7d356da490abcbe5b6f052b1c4b)](https://www.codacy.com/gh/UndernetIRC/cservice-api/dashboard?utm_source=github.com&utm_medium=referral&utm_content=UndernetIRC/cservice-api&utm_campaign=Badge_Grade) [![Codacy Badge](https://app.codacy.com/project/badge/Coverage/7399b7d356da490abcbe5b6f052b1c4b)](https://www.codacy.com/gh/UndernetIRC/cservice-api/dashboard?utm_source=github.com&utm_medium=referral&utm_content=UndernetIRC/cservice-api&utm_campaign=Badge_Coverage)

# Channel Services API

> **Warning**
>
> THIS IS A WORK IN PROGRESS. The API is not stable and may change at any time.
> DO NOT USE IN PRODUCTION.

## Requirements

-   Go >= 1.22 (for compiling)
-   PostgreSQL >= 11.0 (for running)
-   Valkey (opensource redis)

## Configuration

The API can be configured using either a YAML configuration file or environment variables. Environment variables take precedence over
the configuration file.

### Configuration File

1. Copy `config.yml.example` to `config.yml`:

```bash
cp config.yml.example config.yml
```

2. Edit `config.yml` to configure your settings. The configuration file supports all settings shown in the example file.

### Environment Variables

All configuration options can be set using environment variables. The environment variables follow this pattern:

```
CSERVICE_<SECTION>_<KEY>
```

For example:

```bash
# Server configuration
export CSERVICE_SERVICE_HOST=localhost
export CSERVICE_SERVICE_PORT=8080
export CSERVICE_SERVICE_API_PREFIX=api

# Database configuration
export CSERVICE_DATABASE_HOST=localhost
export CSERVICE_DATABASE_PORT=5432
export CSERVICE_DATABASE_USERNAME=cservice
export CSERVICE_DATABASE_PASSWORD=cservice
export CSERVICE_DATABASE_NAME=cservice

# Redis configuration
export CSERVICE_REDIS_HOST=localhost
export CSERVICE_REDIS_PORT=6379
export CSERVICE_REDIS_PASSWORD=
export CSERVICE_REDIS_DATABASE=0
```

### JWT Configuration

For JWT authentication, you need to generate RSA key pairs:

```bash
# Generate access token keys
openssl genrsa -out access_jwt.key 4096
openssl rsa -in access_jwt.key -pubout -out access_jwt.pub

# Generate refresh token keys
openssl genrsa -out refresh_jwt.key 4096
openssl rsa -in refresh_jwt.key -pubout -out refresh_jwt.pub
```

Configure the JWT settings in `config.yml`:

```yaml
jwt:
    signing_method: "RS256"
    signing_key: /path/to/access_jwt.key
    public_key: /path/to/access_jwt.pub
    refresh_signing_key: /path/to/refresh_jwt.key
    refresh_public_key: /path/to/refresh_jwt.pub
```

Or using environment variables:

```bash
export CSERVICE_SERVICE_JWT_SIGNING_METHOD=RS256
export CSERVICE_SERVICE_JWT_SIGNING_KEY=/path/to/access_jwt.key
export CSERVICE_SERVICE_JWT_PUBLIC_KEY=/path/to/access_jwt.pub
export CSERVICE_SERVICE_JWT_REFRESH_SIGNING_KEY=/path/to/refresh_jwt.key
export CSERVICE_SERVICE_JWT_REFRESH_PUBLIC_KEY=/path/to/refresh_jwt.pub
```

The JWKS can be downloaded from `<site>/.well-known/jwks.json`.
NOTE: The JWKS is only available when using RS256.

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

### Database Development

This project uses [sqlc](https://docs.sqlc.dev/en/stable/) to generate Go code from SQL queries.

#### Creating New Migrations

The database schema is defined in `db/migrations/*.sql`. Do _NOT_ modify existing migration files if a schema change is necessary.
Instead, create new migration files:

```bash
migrate create -ext sql -dir db/migrations <migration_name>
```

This will create two new migration files in `db/migrations` with the current timestamp for migrating up and down. Edit these files to
add your SQL statements.

#### Generating Database Code

To generate the Go code from the migrations and SQL queries:

```bash
make generate-sqlc
```

After generating the code, you may need to update the `service.go` file in `models` to match the interface defined in
`models/querier.go`.

#### Generating Test Mocks

After changing SQL queries or schema, update the database mocks for unit tests:

```bash
make generate-mocks
```

### Running the Service

#### Development Mode with Live Reload

```bash
make watch
```

#### Production Mode

```bash
make build
bin/cservice-api -config </path/to/config.yml>
```

### Testing

#### Unit Tests

```bash
make test
```

#### Integration Tests

```bash
make integration-test
```

#### Linting

```bash
make lint
```

## API Documentation

The API documentation is available at `/docs` when the service is running. It provides a Swagger UI interface for exploring and
testing the API endpoints.

## Contributing

1. Fork the repository
2. Create your feature branch
3. Make your changes
4. Run tests and linting
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
