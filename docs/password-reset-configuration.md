# Password Reset Token Configuration

This document describes the configuration options available for the password reset token system in the CService API.

## Configuration Options

The password reset token system can be configured using environment variables or configuration files. All configuration keys use the `CSERVICE_` prefix when set as environment variables.

### Token Length

**Configuration Key:** `service.password_reset.token_length`
**Environment Variable:** `CSERVICE_SERVICE_PASSWORD_RESET_TOKEN_LENGTH`
**Type:** Integer
**Default:** `32`
**Valid Range:** `16` to `128`

Controls the length of generated password reset tokens. Longer tokens provide better security but may be less user-friendly.

**Security Considerations:**

- Minimum of 16 characters ensures adequate entropy
- Maximum of 128 characters prevents excessive token size
- Recommended: Use default value of 32 for good balance of security and usability

### Token Lifetime

**Configuration Key:** `service.password_reset.token_lifetime_minutes`
**Environment Variable:** `CSERVICE_SERVICE_PASSWORD_RESET_TOKEN_LIFETIME_MINUTES`
**Type:** Integer (minutes)
**Default:** `60` (1 hour)
**Valid Range:** `1` to `1440` (24 hours)

Determines how long password reset tokens remain valid after creation.

**Security Considerations:**

- Shorter lifetimes reduce the window for token abuse
- Longer lifetimes improve user experience but increase security risk
- Recommended: 60 minutes (default) for most use cases

### Cleanup Interval

**Configuration Key:** `service.password_reset.cleanup_interval_hours`
**Environment Variable:** `CSERVICE_SERVICE_PASSWORD_RESET_CLEANUP_INTERVAL_HOURS`
**Type:** Integer (hours)
**Default:** `24` (24 hours)
**Valid Range:** `1` to `168` (1 week)

Controls how frequently the system cleans up expired tokens from the database.

**Performance Considerations:**

- More frequent cleanup reduces database size but increases CPU usage
- Less frequent cleanup may lead to database bloat
- Recommended: 24 hours (default) for most deployments

### Maximum Tokens Per User

**Configuration Key:** `service.password_reset.max_tokens_per_user`
**Environment Variable:** `CSERVICE_SERVICE_PASSWORD_RESET_MAX_TOKENS_PER_USER`
**Type:** Integer
**Default:** `3`
**Valid Range:** `1` to `10`

Limits the number of active password reset tokens a single user can have simultaneously.

**Security Considerations:**

- Lower limits prevent token flooding attacks
- Higher limits improve user experience for legitimate users
- Recommended: 3 (default) provides good balance

## Configuration Examples

### Environment Variables

```bash
# Set token length to 64 characters
export CSERVICE_SERVICE_PASSWORD_RESET_TOKEN_LENGTH=64

# Set token lifetime to 30 minutes
export CSERVICE_SERVICE_PASSWORD_RESET_TOKEN_LIFETIME_MINUTES=30

# Set cleanup interval to 12 hours
export CSERVICE_SERVICE_PASSWORD_RESET_CLEANUP_INTERVAL_HOURS=12

# Set max tokens per user to 5
export CSERVICE_SERVICE_PASSWORD_RESET_MAX_TOKENS_PER_USER=5
```

### Configuration File (YAML)

```yaml
service:
    password_reset:
        token_length: 64
        token_lifetime_minutes: 30
        cleanup_interval_hours: 12
        max_tokens_per_user: 5
```

### Configuration File (JSON)

```json
{
    "service": {
        "password_reset": {
            "token_length": 64,
            "token_lifetime_minutes": 30,
            "cleanup_interval_hours": 12,
            "max_tokens_per_user": 5
        }
    }
}
```

## Security Best Practices

1. **Token Length**: Use at least 32 characters for production environments
2. **Token Lifetime**: Keep as short as practical for your use case (recommended: 30-60 minutes)
3. **Cleanup Interval**: Run cleanup at least daily to prevent database bloat
4. **Max Tokens**: Limit to 3-5 tokens per user to prevent abuse

## Validation

The system automatically validates all configuration values:

- **Token Length**: Must be between 16 and 128 characters
- **Token Lifetime**: Must be between 1 minute and 24 hours
- **Cleanup Interval**: Must be between 1 hour and 1 week
- **Max Tokens**: Must be between 1 and 10 tokens per user

Invalid configuration values will cause the application to fail to start with a descriptive error message.

## Monitoring

The password reset token system provides statistics that can be monitored:

- Total number of tokens in the system
- Number of active (unexpired, unused) tokens
- Number of expired tokens
- Number of used tokens

These statistics are available through the `GetTokenStats()` method and are logged during cleanup operations.

## Performance Impact

- **Token Generation**: Minimal CPU impact using crypto/rand
- **Token Validation**: Single database query per validation
- **Cleanup Operations**: Periodic database maintenance (configurable frequency)
- **Database Storage**: Approximately 100-200 bytes per token record

## Migration Notes

When upgrading from systems without password reset tokens:

1. The database migration will automatically create the required table
2. Default configuration values will be applied if not explicitly set
3. No existing functionality is affected
4. The cleanup service will start automatically with the application
