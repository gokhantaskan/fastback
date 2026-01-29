# Design: Health Database Check

## Context

The health endpoint is used by load balancers and monitoring systems. Currently it's a simple
static response that doesn't reflect actual system state.

## Goals / Non-Goals

**Goals:**
- Verify database connectivity on each health check
- Return structured response with component-level status
- Return 503 when database is unreachable (so load balancers route traffic away)

**Non-Goals:**
- Deep health checks (query latency, connection pool stats)
- Caching health status
- Authentication on health endpoint (must remain public for load balancers)

## Decisions

### Decision 1: Use SELECT 1 for database check

Execute `SELECT 1` via SQLAlchemy text() to verify connectivity. This is:
- Lightweight (no table access)
- Database-agnostic
- Standard practice for health checks

### Decision 2: Fail fast on DB error

If the database check fails, return 503 immediately. Don't retry or cache—health checks
should reflect real-time state.

### Decision 3: Structured response format

Return `{"status": "ok|unhealthy", "database": "ok|error"}` to support future
component additions (redis, external services) without breaking consumers.
