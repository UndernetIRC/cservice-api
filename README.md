# Channel Services API

[![CI](https://github.com/UndernetIRC/cservice-api/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/UndernetIRC/cservice-api/actions/workflows/ci.yml) [![Codacy Badge](https://app.codacy.com/project/badge/Grade/7399b7d356da490abcbe5b6f052b1c4b)](https://www.codacy.com/gh/UndernetIRC/cservice-api/dashboard?utm_source=github.com&utm_medium=referral&utm_content=UndernetIRC/cservice-api&utm_campaign=Badge_Grade) [![Codacy Badge](https://app.codacy.com/project/badge/Coverage/7399b7d356da490abcbe5b6f052b1c4b)](https://www.codacy.com/gh/UndernetIRC/cservice-api/dashboard?utm_source=github.com&utm_medium=referral&utm_content=UndernetIRC/cservice-api&utm_campaign=Badge_Coverage)

A modern, RESTful API service for IRC Channel Services management, providing secure authentication, channel registration, user management, and administrative functions for IRC networks.

> **Warning**
>
> THIS IS A WORK IN PROGRESS. The API is not stable and may change at any time.
> DO NOT USE IN PRODUCTION.

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Requirements](#requirements)
- [Configuration](#configuration)
- [Docker Setup](#docker-setup)
- [API Documentation](#api-documentation)
- [Security](#security)
- [Contributing](#contributing)
- [Additional Documentation](#additional-documentation)
- [License](#license)

## Overview

### What is Channel Services API?

The Channel Services API is a Go-based RESTful service that modernizes IRC channel management operations. It provides:

- **User Authentication**: JWT-based authentication with RSA key support
- **Channel Management**: Registration, configuration, and administrative controls
- **User Management**: Account creation, password resets, and profile management
- **Administrative Tools**: Role-based access control and system administration
- **2FA Support**: TOTP and backup code authentication
- **Rate Limiting**: Protection against abuse and spam
- **Comprehensive Logging**: Audit trails and monitoring capabilities

### Key Features

- 🔐 **Secure Authentication**: RSA-signed JWT tokens with refresh token support
- 📊 **Comprehensive Metrics**: OpenTelemetry integration for monitoring
- 🛡️ **Security First**: Input validation, SQL injection protection, rate limiting
- 🏗️ **Clean Architecture**: Modular design with dependency injection
- 📝 **Extensive Testing**: Unit and integration tests with high coverage
- 🐳 **Docker Ready**: Complete containerization with docker-compose
- 📖 **API Documentation**: Interactive Swagger/OpenAPI documentation
- 🔄 **Channel Manager Change**: Secure workflow for transferring channel ownership with email confirmation

## Quick Start

Get the API running in under 5 minutes:

```bash
# Clone the repository
git clone https://github.com/UndernetIRC/cservice-api.git
cd cservice-api

# Start services with Docker
docker-compose up -d

# The API will be available at http://localhost:8080
# API docs at http://localhost:8080/docs
# Mailpit (email testing) at http://localhost:8025
```

For detailed development setup, see **[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)**.

## Requirements

### Runtime Requirements
- Go >= 1.24 (for compiling)
- PostgreSQL >= 11.0 (for running)
- Valkey (opensource Redis alternative)

### Development Tools
- [migrate](https://github.com/golang-migrate/migrate) - Database migrations
- [sqlc](https://sqlc.dev/) - Type-safe SQL code generation
- [air](https://github.com/air-verse/air) - Live reload for development

### Supported Platforms
- Linux (amd64, arm64)
- FreeBSD (amd64)
- macOS (Intel, Apple Silicon)
- Windows (amd64)
- Docker containers

## Configuration

The API can be configured using either a YAML configuration file or environment variables. Environment variables take
precedence over the configuration file.

### Quick Configuration

```bash
# Copy example configuration
cp config.yml.example config.yml

# Generate JWT keys
openssl genrsa -out access_jwt.key 4096
openssl rsa -in access_jwt.key -pubout -out access_jwt.pub
openssl genrsa -out refresh_jwt.key 4096
openssl rsa -in refresh_jwt.key -pubout -out refresh_jwt.pub
```

### Environment Variables

All configuration options can be set using environment variables following the pattern:

```
CSERVICE_<SECTION>_<KEY>
```

**Example:**

```bash
# Server configuration
export CSERVICE_SERVICE_HOST=localhost
export CSERVICE_SERVICE_PORT=8080

# Database configuration
export CSERVICE_DATABASE_HOST=localhost
export CSERVICE_DATABASE_PORT=5432
export CSERVICE_DATABASE_USERNAME=cservice
export CSERVICE_DATABASE_PASSWORD=cservice
export CSERVICE_DATABASE_NAME=cservice
```

### JWT Configuration

Configure JWT in `config.yml`:

```yaml
jwt:
    signing_method: "RS256"
    signing_key: /path/to/access_jwt.key
    public_key: /path/to/access_jwt.pub
    refresh_signing_key: /path/to/refresh_jwt.key
    refresh_public_key: /path/to/refresh_jwt.pub
```

The JWKS endpoint is available at `/.well-known/jwks.json` (RS256 only).

## Docker Setup

### Container Images

Pre-built container images are published to GitHub Container Registry:

```bash
docker pull ghcr.io/undernetirc/cservice-api:latest
```

Multi-architecture images (amd64, arm64) are available for each [release](https://github.com/UndernetIRC/cservice-api/pkgs/container/cservice-api).

### Quick Start with Docker Compose

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f api

# Stop services
docker-compose down
```

### Services Included

- **API Service**: The main Channel Services API (port 8080)
- **PostgreSQL**: Database server (port 5432)
- **Valkey**: Redis-compatible cache (port 6379)
- **Mailpit**: Email testing interface (ports 1025/8025)

## API Documentation

The API provides comprehensive documentation and testing tools:

### Interactive Documentation

- **Swagger UI**: `http://localhost:8080/docs` - Interactive API explorer with request/response examples
- **OpenAPI Spec**: `http://localhost:8080/docs/swagger.json` - Machine-readable API specification
- **JWKS Endpoint**: `http://localhost:8080/.well-known/jwks.json` - JWT public keys for token verification

### Testing Tools

**Postman Collection**: A complete Postman collection is available in [docs/postman/](docs/postman/) covering all API endpoints and workflows:
- Authentication (JWT and API keys)
- User management
- Channel operations
- Administrative functions
- 2FA and password reset flows

**Quick Start:**
1. Import `docs/postman/Complete-API.postman_collection.json` into Postman
2. Configure environment variables (baseUrl, username, password)
3. Run requests with automatic token management

See [docs/postman/README.md](docs/postman/README.md) for detailed usage instructions.

## Security

### Security Features

#### Authentication & Authorization
- **JWT Tokens**: RSA-256 signed tokens with configurable expiration
- **Refresh Tokens**: Secure token renewal without password re-entry
- **2FA Support**: TOTP (Time-based One-Time Password) implementation
- **Backup Codes**: Bcrypt-hashed backup authentication codes
- **Role-Based Access**: Granular permission system for administrative functions

#### Data Protection
- **Password Hashing**: bcrypt with configurable cost factor for passwords and backup codes
- **SQL Injection Prevention**: Type-safe queries via sqlc
- **Input Sanitization**: Comprehensive validation and sanitization
- **HTTPS Enforcement**: TLS termination at reverse proxy level

#### Operational Security
- **Rate Limiting**: Configurable per-user and per-endpoint limits
- **Audit Logging**: Comprehensive security event logging
- **IP Restrictions**: Configurable IP-based access controls
- **Session Management**: Secure session handling with proper invalidation

### Security Best Practices

#### JWT Configuration
```bash
# Generate secure RSA keys
openssl genrsa -out access_jwt.key 4096
openssl rsa -in access_jwt.key -pubout -out access_jwt.pub

# Set appropriate permissions
chmod 600 access_jwt.key
chmod 644 access_jwt.pub
```

#### Environment Security
```bash
# Use strong, unique passwords
export CSERVICE_DATABASE_PASSWORD="$(openssl rand -base64 32)"
export CSERVICE_REDIS_PASSWORD="$(openssl rand -base64 32)"

# Restrict file permissions
chmod 600 .env
chmod 600 config.yml
```

For more security guidelines, see the Security section in [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

## Contributing

We welcome contributions! Please see **[CONTRIBUTING.md](CONTRIBUTING.md)** for detailed guidelines on:

- Development workflow
- Coding standards
- Testing requirements
- Pull request process
- Reporting issues

**Quick Start:**
1. Fork the repository
2. Create a feature branch
3. Make your changes following our coding standards
4. Run tests: `make test && make integration-test && make lint`
5. Submit a pull request

For detailed development setup, see **[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)**.

## Additional Documentation

### Developer Resources
- **[Development Guide](docs/DEVELOPMENT.md)**: Complete setup, testing, architecture, and troubleshooting guide
- **[Contributing Guide](CONTRIBUTING.md)**: How to contribute to the project
- **[Adding API Endpoints](docs/adding-api-endpoints.md)**: Guide for adding new API endpoints
- **[Postman Collections](docs/postman/README.md)**: API testing workflows and examples

### Feature Documentation
- **[API Key Authentication](docs/api-key-authentication.md)**: Service-to-service authentication guide
- **[Password Reset Flow](docs/password-reset-flow.md)**: Password reset implementation and configuration
- **[Password Reset Configuration](docs/password-reset-configuration.md)**: Detailed configuration options
- **[Metrics Guide](docs/metrics-development-guide.md)**: OpenTelemetry metrics and monitoring
- **[Cron Integration](docs/cron-integration.md)**: Scheduled task implementation
- **[Graceful Shutdown](docs/graceful-shutdown.md)**: Server shutdown handling

### Testing & Integration
- **Integration Tests**: Located in `integration/` directory with database-backed tests
- **API Documentation**: Interactive Swagger UI at `/docs` endpoint when server is running

## License

This project is licensed under the MIT License - see the LICENSE file for details.
