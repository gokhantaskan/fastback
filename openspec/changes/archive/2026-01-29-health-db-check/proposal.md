# Proposal: Health Database Check

## Why

The current health endpoint always returns `{"status": "ok"}` regardless of actual system health. This makes it useless for load balancers and monitoring systems that need to detect when the service is unhealthy due to database connectivity issues.

## What Changes

- Enhance `/health` endpoint to verify database connectivity
- Return component-level health status showing database state
- Fail the health check (return 503) when database is unreachable

## Capabilities

### Modified Capabilities
- `health-check`: Enhanced to include database connectivity verification

## Impact

- `app/health/router.py`: Add database session dependency and connectivity check
- `tests/health/test_router.py`: Add tests for healthy and unhealthy database states
