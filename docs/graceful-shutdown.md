# Graceful Shutdown Implementation

This document describes the graceful shutdown implementation in the CService API, designed for Kubernetes deployments.

## Overview

The application now properly handles SIGTERM and SIGINT signals to perform graceful shutdown when running in Kubernetes environments. This ensures that:

1. In-flight HTTP requests are completed
2. Mail queue is properly drained
3. Background workers finish their current tasks
4. Database and Redis connections are cleanly closed

## Implementation Details

### Signal Handling

The application listens for the following signals:

-   `SIGTERM` - Primary shutdown signal sent by Kubernetes
-   `SIGINT` - Interrupt signal (Ctrl+C for local development)

### Shutdown Sequence

When a shutdown signal is received, the following sequence occurs:

1. **HTTP Server Shutdown**: Stop accepting new connections and wait for existing requests to complete
2. **Mail Workers Shutdown**:
    - Close the mail queue channel to stop accepting new mail
    - Wait for all mail workers to finish processing pending emails
    - Close the mail error channel
3. **Background Services**: Wait for all background goroutines to complete using `sync.WaitGroup`
4. **Database Connections**: Close the PostgreSQL connection pool
5. **Redis Connections**: Close the Redis client connections

### Configuration

The shutdown timeout can be configured via:

```yaml
service:
    # Graceful shutdown timeout in seconds (default: 10)
    shutdown_timeout_seconds: 30

    # HTTP server timeout configurations (in seconds)
    http:
        # Timeout for reading request headers - prevents Slowloris attacks (default: 30)
        read_header_timeout_seconds: 30
        # Timeout for reading the entire request (default: 60)
        read_timeout_seconds: 60
        # Timeout for writing the response (default: 60)
        write_timeout_seconds: 60
        # Timeout for keep-alive connections (default: 90)
        idle_timeout_seconds: 90
```

Or via environment variables:

```bash
CSERVICE_SERVICE_SHUTDOWN_TIMEOUT_SECONDS=30
CSERVICE_SERVICE_HTTP_READ_HEADER_TIMEOUT_SECONDS=30
CSERVICE_SERVICE_HTTP_READ_TIMEOUT_SECONDS=60
CSERVICE_SERVICE_HTTP_WRITE_TIMEOUT_SECONDS=60
CSERVICE_SERVICE_HTTP_IDLE_TIMEOUT_SECONDS=90
```

#### HTTP Security Timeouts

The application includes several HTTP timeout configurations to prevent various attacks:

-   **ReadHeaderTimeout**: Prevents Slowloris attacks where attackers send headers slowly
-   **ReadTimeout**: Limits the time for reading the entire request including body
-   **WriteTimeout**: Limits the time for writing responses to prevent slow clients
-   **IdleTimeout**: Limits how long keep-alive connections remain open

### Kubernetes Deployment Considerations

#### Pod Spec Configuration

Ensure your Kubernetes deployment includes appropriate `terminationGracePeriodSeconds`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
    name: cservice-api
spec:
    template:
        spec:
            # Should be higher than your configured shutdown timeout
            terminationGracePeriodSeconds: 60
            containers:
                - name: cservice-api
                  image: your-registry/cservice-api:latest
                  env:
                      - name: CSERVICE_SERVICE_SHUTDOWN_TIMEOUT_SECONDS
                        value: "30"
```

#### Health Checks

The application provides a health check endpoint at `/health-check` that should be used for:

1. **Readiness Probe**: To ensure the pod is ready to receive traffic
2. **Liveness Probe**: To detect if the application is healthy

Example health check configuration:

```yaml
readinessProbe:
    httpGet:
        path: /health-check
        port: 8080
    initialDelaySeconds: 5
    periodSeconds: 10
    timeoutSeconds: 5
    failureThreshold: 3

livenessProbe:
    httpGet:
        path: /health-check
        port: 8080
    initialDelaySeconds: 30
    periodSeconds: 30
    timeoutSeconds: 10
    failureThreshold: 5
```

## Background Services

### Mail Queue Workers

The mail service creates multiple worker goroutines that process emails from a buffered channel. During shutdown:

1. The mail queue channel is closed
2. Workers finish processing any emails already in the queue
3. Workers exit when the channel is drained
4. The error handling goroutine stops when signaled

### Database Connections

PostgreSQL connections use `pgxpool` which properly handles connection cleanup during shutdown.

### Redis Connections

Redis connections are explicitly closed during shutdown with error logging if the close operation fails.

## Best Practices

1. **Shutdown Timeout**: Set the shutdown timeout slightly lower than Kubernetes `terminationGracePeriodSeconds`
2. **Graceful Degradation**: Services should handle shutdown signals gracefully without losing data
3. **Monitoring**: Use proper logging to monitor shutdown behavior in production
4. **Testing**: Test graceful shutdown behavior in staging environments

## Troubleshooting

### Long Shutdown Times

If shutdowns are taking too long:

1. Check mail queue size - large queues take time to drain
2. Verify database query performance
3. Check for hanging goroutines in application logs

### Forced Termination

If the application doesn't shut down within `terminationGracePeriodSeconds`, Kubernetes will send SIGKILL. Monitor logs for:

```
Shutdown timeout reached, some services may not have stopped gracefully
```

This indicates the timeout needs to be increased or there are stuck background processes.

### Mail Queue Behavior

The mail queue will:

-   Process all pending emails during shutdown
-   Log each email processing attempt
-   Complete gracefully when the queue is empty

Monitor mail worker logs:

```
Mail worker 1 processing email to user@example.com
Mail worker 1 successfully sent email to user@example.com
Mail worker 1 stopped
```

## Migration from Previous Version

If upgrading from a version without graceful shutdown:

1. Update your Kubernetes deployment with appropriate `terminationGracePeriodSeconds`
2. Configure the shutdown timeout via environment variables or config file
3. Monitor application logs during deployments to ensure clean shutdowns
4. Test rolling updates to verify zero-downtime deployments
