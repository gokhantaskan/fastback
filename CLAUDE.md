# CLAUDE.md

Guidance for AI agents and developers working with this codebase.

## Project Overview

FastBack is a FastAPI backend with Firebase authentication, SQLModel ORM, and SQLAdmin panel. Uses Docker for development.

**Tech Stack:** FastAPI, SQLModel, PostgreSQL, Alembic, Firebase Auth, SQLAdmin, Resend (email), Docker

## Commands

```bash
# Development
make up              # Start dev server (runs migrations automatically)
make down            # Stop containers
make sh              # Shell into container

# Code quality
make fmt             # Format with Ruff
make lint            # Lint check
make fix             # Auto-fix lint issues

# Testing
make test            # Run pytest
make test-cov        # With coverage

# Migrations
make migrate                   # Apply migrations
make migrate-new MSG="message" # Create new migration
```

## Architecture

```
app/
├── main.py          # FastAPI entry point
├── admin/           # SQLAdmin UI and authentication
├── alembic/         # Database migrations
├── api/             # Routes and HTTP handling
├── core/            # Auth, config, deps (all *Dep type aliases)
├── db/              # Database engine and sessions
├── models/          # SQLModel schemas
└── services/        # Business logic services
tests/               # Pytest test suite
docs/                # Documentation
scripts/             # Utility scripts
```

## Key Patterns

### Dependency Injection

All dependencies are centralized in `app/core/deps.py`. Import from there:

```python
from app.core.deps import SessionDep, CurrentUserDep, SettingsDep, FirebaseAuthDep
```

Available dependencies:

- `SessionDep` - Database session
- `CurrentUserDep` - Authenticated user (from Firebase token)
- `SettingsDep` - Application settings
- `FirebaseAuthDep` - Firebase auth service

### Model Schema Pattern

Each model follows: `Base` → `Table` → `Create/Read/Update` schemas. See existing models in `app/models/` for examples.

### Route Configuration

Routes use centralized config from `app/core/constants.py`. Add new routes by:

1. Create route module in `app/api/routes/`
2. Add config to `constants.py`
3. Include in `app/api/router.py`

### Adding New Models

1. Create model file in `app/models/`
2. Import in `app/models/__init__.py`
3. Run `make migrate-new MSG="add X"` then `make migrate`

### Exception Handling

The app uses a unified exception system (`app/core/exceptions.py`) with automatic HTTP status code mapping. All exceptions inherit from `AppException` and are automatically converted to JSON responses.

**Usage:**

```python
from app.core.exceptions import UserNotFoundError, EmailExistsError

# In route handlers or services
if not user:
    raise UserNotFoundError("User not found")
```

**Exception Categories:**

- **Authentication (401)**: `AuthenticationError`, `InvalidCredentialsError`, `InvalidTokenError`, `SessionCookieError`, `SessionExpiredError`
- **Authorization (403)**: `AuthorizationError`, `UserDisabledError`, `UserInactiveError`
- **Not Found (404)**: `NotFoundError`, `UserNotFoundError`
- **Conflict (409)**: `ConflictError`, `EmailExistsError`
- **Validation (400)**: `ValidationError`, `WeakPasswordError`, `PasswordPolicyError`, `BadRequestError`, `EmailVerificationError`
- **Rate Limit (429)**: `RateLimitError`
- **External Service (502)**: `ExternalServiceError`, `ProviderError`
- **Internal (500)**: `InternalError`

All exceptions accept a custom `message` parameter. `PasswordPolicyError` also accepts an optional `requirements` list.

Exception handlers in `app/core/exception_handlers.py` automatically convert exceptions to JSON responses with format: `{"type": error_type, "message": message}`.

## Principles

- **Single Responsibility**: Each module has one purpose
- **Open/Closed**: Extend via new modules, don't modify existing
- **Dependency Inversion**: Depend on abstractions (`SessionDep`, `CurrentUserDep`)

## Testing

Tests use dependency overrides for isolation. See `tests/conftest.py` for fixtures.

## Environment

See `.env.example` for required variables (database, Firebase, admin credentials, etc.)
