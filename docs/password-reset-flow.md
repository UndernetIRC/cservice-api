# Password Reset Flow Documentation

This document describes the complete password reset functionality implemented in the cservice-api.

## Overview

The password reset system provides a secure way for users to reset their passwords via email verification. The flow consists of two main endpoints and email notification functionality.

## Endpoints

### 1. Request Password Reset

**Endpoint:** `POST /api/v1/auth/password-reset`

**Purpose:** Initiates a password reset request by sending a reset link to the user's email address.

**Request Body:**

```json
{
    "email": "user@example.com"
}
```

**Response:**

- Always returns `200 OK` regardless of whether the email exists (prevents email enumeration attacks)
- Returns the same message: "If the email address exists in our system, you will receive a password reset link shortly."

**Security Features:**

- Email enumeration protection (always returns success)
- Rate limiting through token manager (max tokens per user)
- Configurable token expiration

### 2. Reset Password

**Endpoint:** `POST /api/v1/auth/reset-password`

**Purpose:** Completes the password reset using the token received via email.

**Request Body:**

```json
{
    "token": "reset-token-from-email",
    "new_password": "NewSecurePassword123!",
    "confirm_password": "NewSecurePassword123!"
}
```

**Validation Rules:**

- `token`: Required
- `new_password`: Required, minimum 10 characters, maximum 72 characters
- `confirm_password`: Required, must match `new_password`

**Response:**

- `200 OK`: Password successfully reset
- `400 Bad Request`: Validation errors
- `401 Unauthorized`: Invalid or expired token
- `500 Internal Server Error`: System error

## Email Templates

### HTML Template

Located at: `internal/mail/templates/password_reset/html.tmpl`

Features:

- Modern, responsive design
- UnderNET branding
- Clear call-to-action button
- Fallback link if button doesn't work
- Security information and expiration notice

### Text Template

Located at: `internal/mail/templates/password_reset/text.tmpl`

Features:

- Plain text version for email clients that don't support HTML
- All essential information included
- Clear instructions and security warnings

### Template Variables

Both templates use the following variables:

- `{{.Username}}`: User's username
- `{{.ResetURL}}`: Complete reset URL with token
- `{{.ExpiresIn}}`: Human-readable expiration time (e.g., "60 minutes")
- `{{.Year}}`: Current year for copyright

## Security Implementation

### Token Management

- **Generation:** Cryptographically secure random tokens (32 characters default)
- **Expiration:** Configurable lifetime (60 minutes default)
- **Single Use:** Tokens are marked as used after successful password reset
- **Cleanup:** Automatic cleanup of expired tokens
- **Rate Limiting:** Maximum tokens per user (3 default)

### Password Security

- **Hashing:** Uses the existing password hashing system (bcrypt or MD5 for legacy)
- **Validation:** Strong password requirements enforced
- **Confirmation:** Password confirmation required to prevent typos

### Additional Security Measures

- **Token Invalidation:** All user's reset tokens are invalidated after successful reset
- **Audit Logging:** All password reset attempts are logged
- **Error Handling:** Generic error messages to prevent information leakage

## Configuration

Password reset behavior is controlled by these configuration options:

```yaml
# Token length (16-128 characters)
SERVICE_PASSWORD_RESET_TOKEN_LENGTH: 32

# Token lifetime in minutes (1-1440 minutes)
SERVICE_PASSWORD_RESET_TOKEN_LIFETIME_MINUTES: 60

# Cleanup interval in hours (1-168 hours)
SERVICE_PASSWORD_RESET_CLEANUP_INTERVAL_HOURS: 24

# Maximum tokens per user (1-10 tokens)
SERVICE_PASSWORD_RESET_MAX_TOKENS_PER_USER: 3

# Email service must be enabled
SERVICE_MAIL_ENABLED: true

# Base URL for reset links
SERVICE_BASE_URL: "https://your-domain.com"
```

## Usage Flow

1. **User Request:**

    - User visits forgot password page
    - Enters their email address
    - Submits form to `POST /auth/password-reset`

2. **System Processing:**

    - System validates email format
    - Looks up user by email
    - If user exists:
        - Generates secure reset token
        - Stores token in database with expiration
        - Sends email with reset link
    - Always returns success message

3. **Email Delivery:**

    - User receives email with reset link
    - Link format: `https://domain.com/reset-password?token=TOKEN`
    - Email includes expiration time and security information

4. **Password Reset:**

    - User clicks link or visits reset page
    - Enters new password and confirmation
    - Submits form to `POST /auth/reset-password`
    - System validates token and updates password
    - All user's reset tokens are invalidated

5. **Completion:**
    - User receives success message
    - Can now log in with new password
    - Old tokens are cleaned up automatically

## Database Schema

The password reset functionality uses the `password_reset_tokens` table:

```sql
CREATE TABLE password_reset_tokens (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    token VARCHAR(128) NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at INTEGER,
    last_updated INTEGER NOT NULL,
    deleted BOOLEAN NOT NULL DEFAULT false
);

-- Indexes for performance
CREATE INDEX idx_password_reset_tokens_token ON password_reset_tokens(token);
CREATE INDEX idx_password_reset_tokens_user_id ON password_reset_tokens(user_id);
CREATE INDEX idx_password_reset_tokens_expires_at ON password_reset_tokens(expires_at);
CREATE INDEX idx_password_reset_tokens_created_at ON password_reset_tokens(created_at);
```

## Error Handling

The system handles various error scenarios gracefully:

- **Database errors:** Logged but not exposed to users
- **Email sending failures:** Logged but user still sees success message
- **Token validation errors:** Clear error messages for invalid/expired tokens
- **Password validation errors:** Detailed validation feedback
- **Network issues:** Appropriate HTTP status codes and error messages

## Monitoring and Maintenance

### Metrics to Monitor

- Password reset request rate
- Email delivery success rate
- Token usage success rate
- Failed authentication attempts after resets

### Maintenance Tasks

- **Cleanup Service:** Automatically removes expired tokens
- **Log Analysis:** Monitor for abuse patterns
- **Configuration Tuning:** Adjust timeouts and limits based on usage

## Testing

Comprehensive test coverage includes:

- **Unit Tests:** All controller methods and business logic
- **Integration Tests:** Database operations and email sending
- **Security Tests:** Token validation and abuse prevention
- **Edge Cases:** Expired tokens, invalid emails, malformed requests

Run tests with:

```bash
go test ./controllers -v -run TestAuthenticationController_.*Password
```
