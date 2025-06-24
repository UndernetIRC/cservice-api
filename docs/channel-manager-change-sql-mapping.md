# Channel Manager Change - Legacy SQL Query Mapping

This document maps the legacy PHP SQL queries to their Go implementations in the cservice-api. Each section includes the original SQL query from the PRD, optimization notes, and references to the corresponding Go implementation.

## Table of Contents
1. [Cleanup Expired Requests](#cleanup-expired-requests)
2. [Token Validation and Request Retrieval](#token-validation-and-request-retrieval)
3. [Mark Request as Confirmed](#mark-request-as-confirmed)
4. [Get Channel Info for Confirmation](#get-channel-info-for-confirmation)
5. [Validate User Ownership](#validate-user-ownership)
6. [Get New Manager Details](#get-new-manager-details)
7. [Check Channel Exists](#check-channel-exists)
8. [Check for Existing Pending Requests](#check-for-existing-pending-requests)
9. [Validate New Manager Access Level](#validate-new-manager-access-level)
10. [Check if User Already Owns Channels](#check-if-user-already-owns-channels)
11. [Validate Channel Age](#validate-channel-age)
12. [Check Multiple Managers](#check-multiple-managers)
13. [Insert New Request](#insert-new-request)
14. [Update User Form Cooldown](#update-user-form-cooldown)

## 1. Cleanup Expired Requests

### Legacy SQL (confirm_mgrchange.php:16)
```sql
DELETE FROM pending_mgrchange 
WHERE expiration < date_part('epoch', CURRENT_TIMESTAMP)::int 
AND confirmed = '0';
```

### Go Implementation
- **Location**: `db/queries/manager_change.sql:23-27`
- **Function**: `DeleteExpiredUnconfirmedManagerChangeRequests`
- **Optimization**: Added index recommendation on (expiration, confirmed)

### Usage in Code
- Called in confirmation endpoint before processing tokens
- Ensures expired requests don't accumulate in database

## 2. Token Validation and Request Retrieval

### Legacy SQL (confirm_mgrchange.php:17)
```sql
SELECT * FROM pending_mgrchange 
WHERE crc = $1 
AND expiration >= date_part('epoch', CURRENT_TIMESTAMP)::int 
AND confirmed = '0';
```

### Go Implementation
- **Location**: `db/queries/manager_change.sql:29-44`
- **Function**: `GetPendingManagerChangeRequestByToken`
- **Optimization**: Returns full request details with JOIN to channels table

### Usage in Code
- Used in `GET /channels/{id}/manager-confirm` endpoint
- Validates token and retrieves request details in single query

## 3. Mark Request as Confirmed

### Legacy SQL (confirm_mgrchange.php:25)
```sql
UPDATE pending_mgrchange 
SET confirmed = '1' 
WHERE crc = $1;
```

### Go Implementation
- **Location**: `db/queries/manager_change.sql:46-50`
- **Function**: `ConfirmManagerChangeRequest`
- **Optimization**: Added channel_id to WHERE clause for security

### Usage in Code
- Called after successful token validation
- Updates request status to confirmed for admin review

## 4. Get Channel Info for Confirmation

### Legacy SQL (confirm_mgrchange.php:26-27)
```sql
SELECT pm.channel_id, c.name 
FROM pending_mgrchange pm 
INNER JOIN channels c ON c.id = pm.channel_id 
WHERE pm.crc = $1;
```

### Go Implementation
- **Merged with**: Token validation query (#2 above)
- **Location**: `db/queries/manager_change.sql:29-44`
- **Optimization**: Combined into single query to reduce database round trips

## 5. Validate User Ownership

### Legacy SQL (managerchange.php:362)
```sql
SELECT channels.name, channels.id 
FROM channels, levels 
WHERE levels.channel_id = channels.id 
AND levels.user_id = $1 
AND levels.access = 500 
AND channels.id > 1 
AND channels.registered_ts > 0;
```

### Go Implementation
- **Location**: `db/queries/channel.sql:34-41`
- **Function**: `GetChannelsByUserAccess`
- **Optimization**: Uses proper JOIN syntax, parameterized access level

### Usage in Code
- Controllers check user has level 500 on specific channel
- Used in `RequestManagerChange` method validation

## 6. Get New Manager Details

### Legacy SQL (managerchange.php:169)
```sql
SELECT id, email, user_name 
FROM users 
WHERE lower(user_name) = lower($1);
```

### Go Implementation
- **Location**: `db/queries/user.sql:9-16`
- **Function**: `GetUserByUsername`
- **Optimization**: Added index recommendation on lower(user_name)

### Usage in Code
- Validates new manager exists in `controllers/channel.go:1357`
- Retrieves user details for validation checks

## 7. Check Channel Exists

### Legacy SQL (managerchange.php:197)
```sql
SELECT id 
FROM channels 
WHERE lower(name) = lower($1) 
AND registered_ts > 0;
```

### Go Implementation
- **Location**: Uses existing `GetChannel` by ID
- **Function**: `GetChannel` in `db/queries/channel.sql`
- **Note**: Channel ID provided in API path, not name lookup needed

### Usage in Code
- Channel validation done via ID in REST endpoint
- Registered status checked in validation logic

## 8. Check for Existing Pending Requests

### Legacy SQL (managerchange.php:206, 217)
```sql
-- Check for temporary manager
SELECT * FROM pending_mgrchange 
WHERE channel_id = $1 
AND confirmed = '3';

-- Check for pending requests
SELECT * FROM pending_mgrchange 
WHERE channel_id = $1 
AND confirmed = '1';
```

### Go Implementation
- **Location**: `db/queries/manager_change.sql:8-21`
- **Function**: `GetPendingManagerChangeRequests`
- **Optimization**: Combined queries with status parameter

### Usage in Code
- Called in `controllers/channel.go:1415-1419`
- Prevents duplicate requests for same channel

## 9. Validate New Manager Access Level

### Legacy SQL (managerchange.php:433)
```sql
SELECT users.user_name, users.id 
FROM users, users_lastseen, levels 
WHERE users.id = levels.user_id 
AND levels.channel_id = $1 
AND levels.access = 499 
AND users_lastseen.user_id = users.id 
AND users_lastseen.last_seen > (date_part('epoch', CURRENT_TIMESTAMP)::int - 86400*20) 
ORDER BY users.user_name;
```

### Go Implementation
- **Location**: `db/queries/user.sql:28-37`
- **Function**: `GetUserAccessLevel`
- **Note**: Last seen check moved to application logic

### Usage in Code
- Validates new manager has level 499 in `controllers/channel.go:1369`
- Ensures proper access level before allowing change

## 10. Check if User Already Owns Channels

### Legacy SQL (managerchange.php:443)
```sql
SELECT users.id 
FROM users, levels, channels 
WHERE users.id = $1 
AND levels.user_id = users.id 
AND levels.access = 500 
AND channels.id = levels.channel_id 
AND channels.registered_ts > 0;
```

### Go Implementation
- **Location**: `db/queries/channel.sql:34-41`
- **Function**: `GetChannelsByUserAccess`
- **Optimization**: Uses EXISTS pattern for better performance

### Usage in Code
- Checks in `controllers/channel.go:1399-1410`
- Prevents users from owning multiple channels (permanent changes)

## 11. Validate Channel Age

### Legacy SQL (managerchange.php:279)
```sql
SELECT registered_ts 
FROM channels 
WHERE id = $1;
-- Business rule: Channel must be > 90 days old (86400*90 seconds)
```

### Go Implementation
- **Location**: Uses existing `GetChannel` query
- **Business Logic**: `controllers/channel.go:1376-1381`
- **Calculation**: `time.Since(time.Unix(channel.RegisteredTs, 0)) < 90*24*time.Hour`

### Usage in Code
- Enforces 90-day minimum channel age requirement
- Calculated in application layer for flexibility

## 12. Check Multiple Managers

### Legacy SQL (managerchange.php:295)
```sql
SELECT * FROM channels, levels 
WHERE channels.id = $1 
AND levels.channel_id = channels.id 
AND levels.access = 500;
```

### Go Implementation
- **Location**: `db/queries/user.sql:18-26`
- **Function**: `GetUsersByChannelAccess`
- **Optimization**: Returns count instead of full records

### Usage in Code
- Ensures single manager in `controllers/channel.go:1383-1387`
- Prevents changes when multiple level 500 users exist

## 13. Insert New Request

### Legacy SQL (managerchange.php:327-328)
```sql
INSERT INTO pending_mgrchange (
    channel_id, manager_id, new_manager_id, change_type, 
    opt_duration, reason, expiration, crc, confirmed, from_host
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 0, $9);
```

### Go Implementation
- **Location**: `db/queries/manager_change.sql:52-64`
- **Function**: `InsertManagerChangeRequest`
- **Improvements**: Uses RETURNING clause, proper parameterization

### Usage in Code
- Called in `controllers/channel.go:1420-1433`
- Creates new manager change request with secure token

## 14. Update User Form Cooldown

### Legacy SQL (managerchange.php:352)
```sql
UPDATE users 
SET post_forms = (date_part('epoch', CURRENT_TIMESTAMP)::int + 86400*10) 
WHERE id = $1;
```

### Go Implementation
- **Location**: `db/queries/user.sql:55-59`
- **Function**: `UpdateUserFormCooldown`
- **Note**: Cooldown period made configurable

### Usage in Code
- Sets 10-day cooldown in `controllers/channel.go:1438-1442`
- Prevents rapid successive form submissions

## Implementation Status Summary

All legacy SQL queries have been successfully mapped to Go implementations with the following improvements:

1. **Query Optimization**: Combined related queries, used proper JOINs, added index recommendations
2. **Security**: Proper parameterization, additional validation in WHERE clauses
3. **Performance**: EXISTS instead of COUNT where appropriate, reduced database round trips
4. **Maintainability**: Clear function names, consistent patterns, proper error handling

## Notes for Developers

- All queries follow the sqlc pattern for type safety
- Business logic validation happens in the controller layer
- Database queries focus on data retrieval/modification only
- Error handling follows the established apierrors pattern
- All queries are properly parameterized to prevent SQL injection