# Postman Collections

This directory contains Postman collections for testing the cservice-api endpoints.

## Collections

### API Keys Collection

**File:** `API-Keys.postman_collection.json`

A comprehensive collection for testing API key authentication and management features.

**Included requests:**
- Authentication (Login)
- List available scopes
- Create API key
- List API keys
- Get API key by ID
- Update API key scopes
- Delete API key
- Test API key authentication
- Compare JWT vs API key authentication

## How to Import

### Using Postman Desktop App

1. Open Postman
2. Click **Import** button (top left)
3. Click **Upload Files**
4. Select `API-Keys.postman_collection.json`
5. Click **Import**

### Using Postman CLI

```bash
postman collection import /path/to/API-Keys.postman_collection.json
```

## Configuration

After importing, configure the collection variables:

1. Click on the collection name
2. Select the **Variables** tab
3. Update the following variables:

| Variable | Description | Default Value |
|----------|-------------|---------------|
| `baseUrl` | Your API server URL | `http://localhost:8080/api/v1` |
| `adminUsername` | Admin username | `Admin` |
| `adminPassword` | Admin password | `temPass2020@` |
| `jwtToken` | JWT token (auto-populated) | - |
| `apiKey` | API key (auto-populated) | - |
| `apiKeyId` | API key ID (auto-populated) | - |

## Usage Workflow

### Step 1: Login

1. Run **"Login as Admin"** request in the Authentication folder
2. The JWT token will be automatically saved to the `jwtToken` variable
3. This token is used for all API key management requests

### Step 2: Discover Available Scopes

1. Run **"List Available Scopes"** request
2. Review the available scopes you can assign to API keys:
   - `channels:read`, `channels:write`, `channels:delete`
   - `users:read`, `users:write`, `users:delete`
   - `registrations:read`, `registrations:write`

### Step 3: Create an API Key

1. Run **"Create API Key"** request
2. Modify the request body to set desired scopes:
   ```json
   {
       "name": "My Service API Key",
       "description": "API key for service-to-service authentication",
       "scopes": ["users:read", "channels:read"]
   }
   ```
3. The plain API key and key ID will be automatically saved to variables
4. **Important:** This is the only time you'll see the plain key!

### Step 4: Test API Key Authentication

1. Run **"Get User with API Key"** request
2. This uses the `X-API-Key` header instead of JWT
3. Compare with **"Get User with JWT"** to see both methods work

### Step 5: Manage API Keys

- **List all keys:** Run "List API Keys"
- **Get specific key:** Run "Get API Key by ID"
- **Update scopes:** Run "Update API Key Scopes"
- **Delete key:** Run "Delete API Key"

## Request Details

### Authentication Headers

**JWT Authentication:**
```
Authorization: Bearer {{jwtToken}}
```

**API Key Authentication:**
```
X-API-Key: {{apiKey}}
```

### Example Responses

**Create API Key (Success):**
```json
{
    "id": 1,
    "name": "My Service API Key",
    "key": "cserv_abcdefghijklmnopqrstuvwxyz1234567890ABC",
    "scopes": ["users:read", "channels:read"],
    "created_at": 1696348800,
    "warning": "This key will only be shown once. Store it securely."
}
```

**List Available Scopes:**
```json
[
    {
        "scope": "channels:read",
        "resource": "channels",
        "action": "read",
        "description": "Read channel information and settings"
    },
    {
        "scope": "users:read",
        "resource": "users",
        "action": "read",
        "description": "Read user information"
    }
]
```

**API Key Authentication Error (403):**
```json
{
    "message": "required scope(s) [users:read] not found in API key"
}
```

## Testing Scenarios

### Scenario 1: Valid API Key with Correct Scope

1. Create API key with `users:read` scope
2. Use API key in "Get User with API Key" request
3. **Expected:** 200 OK with user data

### Scenario 2: API Key with Wrong Scope

1. Create API key with only `channels:read` scope
2. Manually update the `apiKey` variable with this key
3. Try "Get User with API Key" request
4. **Expected:** 403 Forbidden - missing `users:read` scope

### Scenario 3: Expired or Deleted API Key

1. Create an API key
2. Delete the key using "Delete API Key"
3. Try to use the deleted key
4. **Expected:** 401 Unauthorized

### Scenario 4: Update API Key Scopes

1. Create API key with `users:read` scope
2. Update scopes to add `users:write`
3. Verify the updated scopes in "Get API Key by ID"
4. **Expected:** API key now has both scopes

## Environment Variables

For managing multiple environments (development, staging, production), you can create Postman environments:

**Development Environment:**
```json
{
    "baseUrl": "http://localhost:8080/api/v1",
    "adminUsername": "Admin",
    "adminPassword": "temPass2020@"
}
```

**Staging Environment:**
```json
{
    "baseUrl": "https://staging-api.example.com/api/v1",
    "adminUsername": "Admin",
    "adminPassword": "your-staging-password"
}
```

**Production Environment:**
```json
{
    "baseUrl": "https://api.example.com/api/v1",
    "adminUsername": "Admin",
    "adminPassword": "your-production-password"
}
```

## Automation with Newman

You can run these collections using Newman (Postman's CLI runner):

### Installation

```bash
npm install -g newman
```

### Run Collection

```bash
# Basic run
newman run API-Keys.postman_collection.json

# With environment
newman run API-Keys.postman_collection.json -e production.postman_environment.json

# With detailed output
newman run API-Keys.postman_collection.json --verbose

# Generate HTML report
newman run API-Keys.postman_collection.json \
    --reporters cli,html \
    --reporter-html-export report.html
```

### CI/CD Integration

```yaml
# GitHub Actions example
- name: Run API Tests
  run: |
    newman run docs/postman/API-Keys.postman_collection.json \
      --env-var "baseUrl=${{ secrets.API_URL }}" \
      --env-var "adminUsername=${{ secrets.ADMIN_USERNAME }}" \
      --env-var "adminPassword=${{ secrets.ADMIN_PASSWORD }}"
```

## Security Notes

1. **Never commit passwords:** Use environment variables or Postman vaults
2. **Rotate API keys:** Regularly delete and recreate API keys
3. **Minimal scopes:** Only assign necessary scopes to each API key
4. **Monitor usage:** Check `last_used_at` timestamps in API key details

## Troubleshooting

### Issue: "jwtToken is empty"

**Solution:** Run the "Login as Admin" request first. The test script automatically saves the token.

### Issue: "apiKey is empty"

**Solution:** Run the "Create API Key" request first. The test script automatically saves the key.

### Issue: 401 Unauthorized

**Causes:**
- JWT token expired (run "Login as Admin" again)
- API key is deleted or invalid
- Missing authentication header

### Issue: 403 Forbidden

**Causes:**
- API key missing required scope
- JWT user doesn't have admin level 1000+
- Wrong authentication method for endpoint

## Additional Resources

- [API Key Authentication Guide](../api-key-authentication.md)
- [CLAUDE.md](../../CLAUDE.md) - Development guide
- [Swagger/OpenAPI Documentation](http://localhost:8080/docs) (when server is running)

## Support

For issues or questions:
1. Check the API documentation: `/docs` endpoint when server is running
2. Review integration tests: `integration/apikey_integration_test.go`
3. Check server logs for detailed error messages
