Channel Services API
====================
> **Warning**
> 
> THIS IS A WORK IN PROGRESS.  The API is not stable and may change at any time.
> DO NOT USE IN PRODUCTION.

# Requirements
- golang >= 1.8 (for compiling)
- PostgreSQL >= 11.0 (for running)
- Redis

# Configuration

Copy `config.yml.example` to `config.yml` and edit it to your liking.

## Generate JWT RSA key pair for access token and refresh token

```bash
openssl genrsa -out jwt.key 4096
openssl rsa -in jwt.key -pubout -out jwt.pub
openssl genrsa -out refresh_jwt.key 4096
openssl rsa -in refresh_jwt.key -pubout -out refresh_jwt.pub
```

## Configure cservice-api with JWT RSA key

Add the following to `config.yml`:

```yaml
jwt:
  signing_method: "RS256"
  signing_key: /path/to/jwt.key
  public_key: /path_to/jwt.pub
  refresh_signing_key: /path/to/jwt.key
  refresh_public_key: /path_to/jwt.pub
```

The JWKS can be downloaded from `<site>/.well-known/jwks.json`.

# Building and running

## Build

```bash
make build
```

Running the service:

```bash 
bin/cservice-api -config </path/to/config.yml>
```

# Development

## Generate database repositories

This project uses [sqlc](https://docs.sqlc.dev/en/stable/) to generate Go code from SQL queries.

The database schema is defined in `db/migrations/*.sql`. Do *NOT* modify existing
migration files if a schema change is necessary. Instead, run the following command:

````bash
migrate create -ext sql -dir db/migrations <migration_name>
````

This will create two new migration files in `db/migrations` with the current timestamp 
for migrating up and down. Edit the files to add the necessary SQL statements.

To generate the Go code from the migrations in `db/migrations` and the SQL queries 
defined in `db/query/*.sql`, run:

```bash
make generate-sqlc
```

After this, you may have to update the `service.go` file in `models` so that it
matches the interface defined in `models/querier.go`.

After changing the SQL queries or schema it may be necessary to update the database
mocks for the unit tests by running:

```bash
make generate-mocks
```
## Unit tests

To run the unit tests, run:

```bash
make test
```

## Integration tests

The integration tests use [dockertest](https://github.com/ory/dockertest).
To run the integration tests, run:

```bash
make integration-test
```

## Live reloading while developing

To run the service with live reloading, run:

```bash
make watch
```
