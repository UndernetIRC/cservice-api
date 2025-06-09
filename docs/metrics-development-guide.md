# Metrics Development Guide

This guide explains how to add new metrics to the cservice-api project for monitoring application performance, security, and business operations.

## Overview

The cservice-api uses OpenTelemetry for observability with three main metric categories:

1. **HTTP Metrics** - Request/response performance and volume
2. **Auth Metrics** - Authentication and security events
3. **Business Metrics** - User behavior and business intelligence

## Metric Categories Explained

### Auth Metrics vs Business Metrics

Many endpoints appear in both auth and business metrics but serve different purposes:

#### Auth Metrics (Security Focus)

- **Purpose**: Security monitoring, threat detection, authentication performance
- **Examples**: Login attempts, token validation, session security
- **Labels**: `username`, `failure_reason`, `token_type`
- **Use Cases**: Detect brute force attacks, monitor auth latency, security alerting

#### Business Metrics (User Behavior Focus)

- **Purpose**: User engagement, product analytics, business intelligence
- **Examples**: User sessions, feature usage, conversion funnels
- **Labels**: `user_id`, `feature`, `operation_type`, `channel_id`
- **Use Cases**: User engagement analysis, feature adoption, business KPIs

#### Example: `/login` endpoint

```go
// Auth Metrics - Security perspective
auth_login_attempts_total{username="john", result="failure", failure_reason="invalid_password"}
auth_login_duration_ms{username="john", result="failure"}

// Business Metrics - User behavior perspective
business_user_sessions_total{user_id="123", session_type="web"}
business_active_users{user_id="123", action="login"}
business_feature_usage_total{feature="user_login", user_id="123"}
```

## Adding New Metrics

### Step 1: Choose the Right Category

**Add to Auth Metrics when:**

- Tracking authentication/authorization events
- Monitoring security-related operations
- Detecting potential security threats
- Measuring auth system performance

**Add to Business Metrics when:**

- Tracking user behavior and engagement
- Measuring business KPIs and conversions
- Analyzing feature usage patterns
- Monitoring business operation success rates

**Add to HTTP Metrics when:**

- Tracking general API performance
- Monitoring request/response patterns
- Measuring infrastructure health

### Step 2: Define Your Metric

Choose the appropriate OpenTelemetry instrument type:

```go
// Counter - Monotonically increasing values
metric.Int64Counter("requests_total")

// Histogram - Distribution of values (latency, sizes)
metric.Float64Histogram("request_duration_ms")

// UpDownCounter - Values that can increase/decrease
metric.Int64UpDownCounter("active_connections")

// Gauge (via ObservableGauge) - Point-in-time values
metric.Int64ObservableGauge("memory_usage_bytes")
```

### Step 3: Add Metric to Package

#### For Auth Metrics

1. **Add to struct** in `internal/metrics/auth_metrics.go`:

```go
type AuthMetrics struct {
    // ... existing metrics
    newAuthMetric metric.Int64Counter
}
```

2. **Initialize in constructor**:

```go
func NewAuthMetrics(config AuthMetricsConfig) (*AuthMetrics, error) {
    // ... existing initialization

    metrics.newAuthMetric, err = config.Meter.Int64Counter(
        "auth_new_metric_total",
        metric.WithDescription("Description of what this metric tracks"),
    )
    if err != nil {
        return nil, fmt.Errorf("failed to create new auth metric: %w", err)
    }

    return metrics, nil
}
```

3. **Add recording method**:

```go
func (m *AuthMetrics) RecordNewAuthEvent(ctx context.Context, userID int32, success bool, reason string) {
    attrs := []attribute.KeyValue{
        attribute.Int64("user_id", int64(userID)),
        attribute.String("result", getResultString(success)),
        attribute.String("reason", reason),
    }

    m.newAuthMetric.Add(ctx, 1, metric.WithAttributes(attrs...))
}
```

#### For Business Metrics

1. **Add to struct** in `internal/metrics/business_metrics.go`:

```go
type BusinessMetrics struct {
    // ... existing metrics
    newBusinessMetric metric.Int64Counter
}
```

2. **Initialize in constructor**:

```go
func NewBusinessMetrics(config BusinessMetricsConfig) (*BusinessMetrics, error) {
    // ... existing initialization

    metrics.newBusinessMetric, err = config.Meter.Int64Counter(
        "business_new_metric_total",
        metric.WithDescription("Description of business metric"),
    )
    if err != nil {
        return nil, fmt.Errorf("failed to create new business metric: %w", err)
    }

    return metrics, nil
}
```

3. **Add recording method**:

```go
func (m *BusinessMetrics) RecordNewBusinessEvent(ctx context.Context, userID int32, operation string, success bool) {
    serviceName := "cservice-api"
    result := getResultString(success)

    m.newBusinessMetric.Add(ctx, 1, metric.WithAttributes(
        attribute.String("service", serviceName),
        attribute.String("operation", operation),
        attribute.String("result", result),
        attribute.Int("user_id", int(userID)),
    ))
}
```

### Step 4: Add Middleware Integration

#### For Auth Metrics

Add to `middlewares/auth_metrics.go` in the `recordAuthMetrics` function:

```go
func recordAuthMetrics(ctx context.Context, authMetrics *metrics.AuthMetrics, c echo.Context, requestBody []byte, status int, duration time.Duration) {
    // ... existing logic

    // Add your new endpoint detection
    case strings.Contains(path, "/your-new-endpoint") && method == "POST":
        recordNewAuthMetrics(ctx, authMetrics, c, status, duration, requestBody)
}

// Add new recording function
func recordNewAuthMetrics(ctx context.Context, authMetrics *metrics.AuthMetrics, c echo.Context, status int, duration time.Duration, requestBody []byte) {
    success := status >= 200 && status < 400
    userID := extractUserIDFromContext(c)
    reason := determineReason(status, success)

    authMetrics.RecordNewAuthEvent(ctx, userID, success, reason)
}
```

#### For Business Metrics

Add to `middlewares/business_metrics.go` in the `recordBusinessMetrics` function:

```go
func recordBusinessMetrics(ctx context.Context, businessMetrics *metrics.BusinessMetrics, c echo.Context, requestBody []byte, status int, duration time.Duration) {
    // ... existing logic

    // Add your new endpoint detection
    case strings.Contains(path, "/your-new-endpoint") && method == "POST":
        recordNewBusinessMetrics(ctx, businessMetrics, c, status, userID, requestBody)
}

// Add new recording function
func recordNewBusinessMetrics(ctx context.Context, businessMetrics *metrics.BusinessMetrics, c echo.Context, status int, userID int32, requestBody []byte) {
    success := status >= 200 && status < 400
    operation := extractOperationFromRequest(requestBody)

    businessMetrics.RecordNewBusinessEvent(ctx, userID, operation, success)
}
```

### Step 5: Add Tests

Create comprehensive tests for your new metrics:

```go
func TestNewMetric_RecordEvent(t *testing.T) {
    tests := []struct {
        name     string
        userID   int32
        success  bool
        reason   string
        expected map[string]interface{}
    }{
        {
            name:    "successful_event",
            userID:  123,
            success: true,
            reason:  "success",
            expected: map[string]interface{}{
                "user_id": int64(123),
                "result":  "success",
                "reason":  "success",
            },
        },
        // Add more test cases
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Test implementation
            meter := metric.NewNoopMeterProvider().Meter("test")
            metrics, err := NewAuthMetrics(AuthMetricsConfig{
                Meter:       meter,
                ServiceName: "test-service",
            })
            require.NoError(t, err)

            ctx := context.Background()
            metrics.RecordNewAuthEvent(ctx, tt.userID, tt.success, tt.reason)

            // Verify metrics were recorded (implementation depends on test setup)
        })
    }
}
```

## Best Practices

### Metric Naming

Follow OpenTelemetry conventions:

```go
// Good - Clear, descriptive names
"auth_login_attempts_total"
"business_user_registrations_total"
"http_request_duration_ms"

// Bad - Unclear or inconsistent
"logins"
"user_stuff_count"
"req_time"
```

### Label Guidelines

**Do:**

- Use consistent label names across metrics
- Include service name for multi-service environments
- Add contextual information for filtering/grouping

**Don't:**

- Include high-cardinality values (UUIDs, timestamps)
- Add sensitive information (passwords, tokens)
- Create too many label combinations

```go
// Good labels
attribute.String("service", "cservice-api"),
attribute.String("operation", "user_registration"),
attribute.String("result", "success"),
attribute.Int("user_id", int(userID)),

// Bad labels
attribute.String("timestamp", time.Now().String()), // High cardinality
attribute.String("password", password),              // Sensitive data
attribute.String("request_id", uuid.String()),       // High cardinality
```

### Performance Considerations

- **Minimize overhead**: Keep metric recording lightweight
- **Batch operations**: Use context propagation for related metrics
- **Avoid blocking**: Never block request processing for metrics
- **Sample high-volume**: Consider sampling for very high-frequency events

```go
// Good - Non-blocking, efficient
func (m *Metrics) RecordEvent(ctx context.Context, data EventData) {
    // Quick validation
    if data.UserID <= 0 {
        return
    }

    // Efficient attribute creation
    attrs := []attribute.KeyValue{
        attribute.Int("user_id", int(data.UserID)),
        attribute.String("result", getResultString(data.Success)),
    }

    // Non-blocking metric recording
    m.counter.Add(ctx, 1, metric.WithAttributes(attrs...))
}
```

## Testing Your Metrics

### Unit Tests

Test metric creation and recording:

```bash
go test ./internal/metrics -v
go test ./middlewares -v -run=".*Metrics.*"
```

### Integration Tests

Test middleware integration:

```bash
go test ./routes -v
```

### Manual Testing

1. **Start the application** with telemetry enabled
2. **Make requests** to your new endpoints
3. **Check metrics endpoint**: `GET /metrics` (if Prometheus enabled)
4. **Verify in monitoring**: Check Grafana/Prometheus for new metrics

## Monitoring and Alerting

### Grafana Dashboards

Create dashboard panels for your new metrics:

```promql
# Counter rate
rate(auth_new_metric_total[5m])

# Histogram percentiles
histogram_quantile(0.95, rate(business_operation_duration_ms_bucket[5m]))

# Gauge current value
business_active_users
```

### Alerting Rules

Set up alerts for critical metrics:

```yaml
# Prometheus alerting rule
- alert: HighAuthFailureRate
  expr: rate(auth_login_failures_total[5m]) > 10
  for: 2m
  labels:
      severity: warning
  annotations:
      summary: "High authentication failure rate detected"
```

## Troubleshooting

### Common Issues

1. **Metrics not appearing**: Check telemetry configuration and middleware order
2. **High cardinality**: Review label usage, avoid unique identifiers
3. **Performance impact**: Profile metric recording, consider sampling
4. **Missing context**: Ensure proper context propagation through middleware

### Debug Commands

```bash
# Check metric creation
go test ./internal/metrics -v -run="TestNew.*Metrics"

# Verify middleware integration
go test ./middlewares -v -run=".*Metrics.*"

# Test full integration
go test ./routes -v
```

## Examples

### Complete Example: Adding Channel Creation Metrics

1. **Add to BusinessMetrics struct**:

```go
channelCreations metric.Int64Counter
```

2. **Initialize in constructor**:

```go
metrics.channelCreations, err = config.Meter.Int64Counter(
    "business_channel_creations_total",
    metric.WithDescription("Total number of channel creation attempts"),
)
```

3. **Add recording method**:

```go
func (m *BusinessMetrics) RecordChannelCreation(ctx context.Context, userID int32, channelType string, success bool) {
    serviceName := "cservice-api"
    result := getResultString(success)

    m.channelCreations.Add(ctx, 1, metric.WithAttributes(
        attribute.String("service", serviceName),
        attribute.String("channel_type", channelType),
        attribute.String("result", result),
        attribute.Int("user_id", int(userID)),
    ))
}
```

4. **Add middleware detection**:

```go
case strings.Contains(path, "/channels") && method == "POST":
    recordChannelCreationMetrics(ctx, businessMetrics, c, status, userID, requestBody)
```

5. **Add tests**:

```go
func TestBusinessMetrics_RecordChannelCreation(t *testing.T) {
    // Test implementation
}
```

This comprehensive approach ensures your metrics are properly integrated, tested, and ready for production monitoring.
