# Cron Service Integration

This document explains how the cron service is integrated into the CService API using the robfig/cron library for automated password reset token cleanup and other scheduled tasks.

## Overview

The cron service provides:

- **Password Reset Token Cleanup**: Automatically removes expired password reset tokens
- **Configurable Scheduling**: Uses standard cron expressions
- **Service Integration**: Seamlessly integrates with existing application services
- **Graceful Shutdown**: Properly stops when the application shuts down
- **Production Ready**: Built on the battle-tested robfig/cron library

## Configuration

The cron service is configured through the main application configuration file. Add these settings to your `config.yml`:

```yaml
# config.yml
service:
    # Cron job configuration for scheduled tasks
    cron:
        # Enable/disable cron service (default: false)
        enabled: true
        # Cron expression for password reset token cleanup (default: "0 0 * * *" - daily at midnight)
        # Examples:
        #   "*/5 * * * *"  - Every 5 minutes
        #   "0 */6 * * *"  - Every 6 hours
        #   "0 0 * * *"    - Daily at midnight
        #   "0 0 * * 0"    - Weekly on Sunday at midnight
        password_reset_cleanup: "0 */6 * * *" # Every 6 hours
        # Timezone for cron jobs (default: "UTC")
        timezone: "UTC"

    # Password reset token configuration
    password_reset:
        # Length of generated password reset tokens (default: 32)
        token_length: 32
        # How long password reset tokens are valid in minutes (default: 60)
        token_lifetime_minutes: 60
        # How often to clean up expired tokens in hours (default: 24)
        cleanup_interval_hours: 24
        # Maximum number of active tokens per user (default: 3)
        max_tokens_per_user: 3
```

### Environment Variables

You can also configure via environment variables:

```bash
# Enable cron service
export CSERVICE_SERVICE_CRON_ENABLED=true

# Set cleanup schedule (every 5 minutes for testing)
export CSERVICE_SERVICE_CRON_PASSWORD_RESET_CLEANUP="*/5 * * * *"

# Set timezone
export CSERVICE_SERVICE_CRON_TIMEZONE="America/New_York"
```

## Integration Details

### Startup Sequence

The cron service is integrated into the main application startup in `cmd/cservice-api/main.go`:

1. **Configuration Loading**: Cron config is loaded from Viper
2. **Service Creation**: Cron service is created with the configuration
3. **Job Setup**: Password reset cleanup job is configured
4. **Service Start**: Cron scheduler starts and begins running jobs
5. **Graceful Shutdown**: Service is properly stopped during application shutdown

### Shutdown Process

During application shutdown, the cron service is stopped **first** before other services:

1. **Cron Stop**: All scheduled jobs are stopped
2. **HTTP Server Shutdown**: Server stops accepting new requests
3. **Background Services**: Mail workers and other services stop
4. **Database Cleanup**: Connections are closed gracefully

## Monitoring and Management

### Checking Service Status

The application logs provide information about cron service status:

```
INFO Cron service started successfully jobs=1
INFO Password reset token cleanup job scheduled cron="0 */6 * * *" cleanup_interval=24h0m0s
```

### Job Information

You can view scheduled job information through the service:

```go
// Get information about all scheduled jobs
entries := cronService.GetJobEntries()
for _, entry := range entries {
    fmt.Printf("Job %d: Next run at %v, Schedule: %s\n",
        entry.ID, entry.Next, entry.Schedule)
}
```

### Manual Cleanup Execution

For testing or manual execution, you can run the cleanup once:

```go
ctx := context.Background()
err := cronService.RunPasswordResetCleanupOnce(ctx, queries)
if err != nil {
    log.Printf("Manual cleanup failed: %v", err)
}
```

## Cron Expression Examples

The service supports standard 5-field cron expressions:

| Expression      | Description                    |
| --------------- | ------------------------------ |
| `"*/5 * * * *"` | Every 5 minutes                |
| `"0 * * * *"`   | Every hour (at minute 0)       |
| `"0 */6 * * *"` | Every 6 hours                  |
| `"0 0 * * *"`   | Daily at midnight              |
| `"0 0 * * 0"`   | Weekly on Sunday at midnight   |
| `"0 0 1 * *"`   | Monthly on the 1st at midnight |
| `"0 2 * * 1-5"` | Weekdays at 2 AM               |

## Service Architecture

### Core Components

1. **`cron.Service`**: Main service that manages the scheduler and jobs
2. **`cron.Scheduler`**: Wrapper around robfig/cron with additional functionality
3. **`reset.CleanupService`**: Handles password reset token cleanup logic
4. **`reset.TokenManager`**: Manages password reset token operations

### Integration Flow

```
main.go
├── Load Configuration
├── Create Cron Service
├── Setup Jobs (Password Reset Cleanup)
├── Start Scheduler
├── Register with Shutdown Manager
└── Start HTTP Server

Shutdown:
├── Stop Cron Service
├── Stop HTTP Server
├── Stop Background Services
└── Close Database Connections
```

## Error Handling

The cron service includes comprehensive error handling:

- **Configuration Errors**: Invalid cron expressions or missing config
- **Database Errors**: Connection issues during cleanup operations
- **Job Execution Errors**: Individual job failures don't crash the service
- **Shutdown Errors**: Graceful degradation if shutdown fails

## Performance Considerations

- **Non-blocking**: Cron jobs run in separate goroutines
- **Database Efficient**: Cleanup operations are optimized with proper indexing
- **Memory Safe**: No memory leaks in long-running operations
- **Timezone Aware**: Proper timezone handling for global deployments

## Security

- **No External Dependencies**: Uses only the trusted robfig/cron library
- **Database Security**: All database operations use parameterized queries
- **Logging Security**: No sensitive data logged in cron operations
- **Resource Limits**: Jobs are designed to be resource-efficient

## Development and Testing

### Running Tests

```bash
# Test the cron package
go test ./internal/cron/...

# Test the reset package
go test ./internal/auth/reset/...

# Test the entire application
go test ./...
```

### Development Mode

For development, you might want more frequent cleanup:

```yaml
service:
    cron:
        enabled: true
        password_reset_cleanup: "*/1 * * * *" # Every minute for testing
```

## Troubleshooting

### Common Issues

1. **Service Not Starting**: Check that `service.cron.enabled` is set to `true`
2. **Invalid Cron Expression**: Verify the cron expression format using online validators
3. **Database Connection**: Ensure the database is accessible for cleanup operations
4. **Timezone Issues**: Verify the timezone setting matches your deployment environment

### Debug Logging

The service provides detailed logging for troubleshooting:

```
INFO Cron service started successfully
INFO Password reset token cleanup job scheduled
INFO Running password reset token cleanup
INFO Token cleanup completed deleted_count=42 duration=125ms
```

## Migration from Custom Implementation

If migrating from a custom cron implementation:

1. **Configuration**: Update config to use the new cron section
2. **Dependencies**: Ensure `github.com/robfig/cron/v3` is installed
3. **Custom Jobs**: Use `cronService.AddCustomJob()` for additional scheduled tasks
4. **Testing**: Verify all existing functionality works with the new implementation

This integration provides a robust, production-ready scheduled task system for the CService API.
