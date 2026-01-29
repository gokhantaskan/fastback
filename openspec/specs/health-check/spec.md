# health-check Specification

## Purpose
TBD - created by archiving change health-db-check. Update Purpose after archive.
## Requirements
### Requirement: Database Connectivity Check

The health endpoint SHALL verify database connectivity and MUST report component-level status.

#### Scenario: Database is healthy

- **WHEN** GET /health is called
- **AND** the database is reachable
- **THEN** return HTTP 200
- **AND** response body contains `{"status": "ok", "database": "ok"}`

#### Scenario: Database is unreachable

- **WHEN** GET /health is called
- **AND** the database connection fails
- **THEN** return HTTP 503 (Service Unavailable)
- **AND** response body contains `{"status": "unhealthy", "database": "error"}`

