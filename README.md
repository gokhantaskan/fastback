# FastBack

A FastAPI backend with Docker development environment, Poetry dependency management, and Ruff for linting/formatting.

## Quick Start

```bash
# Copy environment file
cp .env.example .env

# Install dependencies and compile email templates
make install

# Start development server (includes migrations)
make up
```

- API: http://localhost:8000
- Docs: http://localhost:8000/docs
- Admin: http://localhost:8000/admin

## Tech Stack

- **[FastAPI](https://fastapi.tiangolo.com/)** - Modern async web framework
- **[SQLModel](https://sqlmodel.tiangolo.com/)** - SQL database ORM
- **[Alembic](https://alembic.sqlalchemy.org/)** - Database migrations
- **[PostgreSQL](https://www.postgresql.org/)** - Production database
- **[SQLAdmin](https://github.com/aminalaee/sqladmin)** - Admin panel for SQLAlchemy/SQLModel
- **[Firebase Admin](https://firebase.google.com/docs/admin/setup)** - Authentication via Firebase ID tokens
- **[Resend](https://resend.com/)** - Email delivery for password resets
- **[Poetry](https://python-poetry.org/)** - Dependency management
- **[Ruff](https://docs.astral.sh/ruff/)** - Linting & formatting
- **[Docker](https://www.docker.com/)** - Containerization

## Prerequisites

- Docker & Docker Compose

## Getting Started

1. **Clone and navigate to the project:**

   ```bash
   cd fastback
   ```

2. **(Optional) Create environment file:**

   ```bash
   cp .env.example .env
   ```

3. **Start the development server:**

   ```bash
   make up
   ```

   This automatically runs database migrations after starting the containers.

4. **Access the API:**
   - API: http://localhost:8000
   - Docs (Swagger): http://localhost:8000/docs
   - Docs (ReDoc): http://localhost:8000/redoc
   - Admin (SQLAdmin): http://localhost:8000/admin

## Environment Variables

| Variable                         | Required | Description                                                   |
| -------------------------------- | :------: | ------------------------------------------------------------- |
| `DB_USER`                        |   Yes    | PostgreSQL username                                           |
| `DB_PASSWORD`                    |   Yes    | PostgreSQL password                                           |
| `DB_HOST`                        |   Yes    | PostgreSQL host                                               |
| `DB_PORT`                        |   Yes    | PostgreSQL port                                               |
| `DB_NAME`                        |   Yes    | PostgreSQL database name                                      |
| `DATABASE_URL`                   |   Yes    | Full connection string (constructed from values above)        |
| `GOOGLE_APPLICATION_CREDENTIALS` |   Yes    | Path to Firebase service account JSON                         |
| `FIREBASE_API_KEY`               |   Yes    | Firebase API key for Identity Toolkit                         |
| `SESSION_SECRET_KEY`             |   Yes    | Secret key for admin sessions                                 |
| `ADMIN_USERNAME`                 |   Yes    | SQLAdmin username                                             |
| `ADMIN_PASSWORD`                 |   Yes    | SQLAdmin password                                             |
| `RESEND_API_KEY`                 |    No    | Resend API key for password reset emails                      |
| `ENV_NAME`                       |    No    | Environment name (default: `development`)                     |
| `APP_DOMAIN`                     |    No    | Domain for emails (default: `resend.dev`)                     |
| `CLIENT_URL`                     |    No    | Client app URL (default: `http://localhost:3000`)             |
| `CORS_ORIGINS`                   |    No    | Comma-separated allowed origins (default: `*`)                |
| `SESSION_EXPIRES_DAYS`           |    No    | Session cookie expiration in days (default: `5`, range: 1–14) |
| `LOG_LEVEL`                      |    No    | Log level (default: `INFO`)                                   |
| `LOG_JSON`                       |    No    | JSON logs (`true`/`false`, default: `false`)                  |
| `LOG_REQUESTS`                   |    No    | Log each HTTP request (default: `true`)                       |
| `LOG_UVICORN_ACCESS`             |    No    | Uvicorn access logs (default: `false`; enabled if set `true`) |
| `HTTPX_LOG_LEVEL`                |    No    | httpx log level (default: `WARNING`)                          |

## Logging

FastBack configures logging to stdout and includes an HTTP request logging middleware.

- **Request logs**: enabled by default via `LOG_REQUESTS=true`
- **Avoid duplicate access logs**: when `LOG_REQUESTS=true`, Uvicorn access logs default to off (set `LOG_UVICORN_ACCESS=true` to enable)
- **Structured logging**: set `LOG_JSON=true` for JSON output

Example (JSON logs):

```bash
LOG_JSON=true LOG_LEVEL=INFO make up
```

## Firebase Authentication

Firebase Admin SDK is used for token verification. Protected routes require a valid Firebase ID token in the `Authorization` header.

### Setup

1. Download your Firebase service account JSON from the Firebase Console
2. Set `GOOGLE_APPLICATION_CREDENTIALS` to the path of the JSON file

### Protecting Routes

```python
from app.auth.dependencies import CurrentUserDep

@router.get("/protected")
async def protected_route(user: CurrentUserDep):
    return {"user_id": user.id, "email": user.email}
```

### Making Authenticated Requests

```bash
curl -H "Authorization: Bearer YOUR_FIREBASE_ID_TOKEN" http://localhost:8000/users/me
```

## Database Migrations

This project uses Alembic for database schema migrations with autogenerate support.

### Creating Migrations

After modifying models in `app/models/`, create a new migration:

```bash
make migrate-new MSG="add email field to user"
```

This generates a migration file in `alembic/versions/` with the detected changes.

### Applying Migrations

```bash
make migrate
```

### Rolling Back

```bash
make migrate-down
```

### Viewing History

```bash
make migrate-history
```

## SQLAdmin

SQLAdmin is mounted at `/admin`.

## Make Commands

Run `make help` to see all available commands:

| Command                          | Description                                          |
| -------------------------------- | ---------------------------------------------------- |
| `make install`                   | Install dependencies, compile emails, setup hooks    |
| `make compile-emails`            | Compile email templates (inline CSS, minify)         |
| `make up`                        | Start Docker dev server (runs migrations)            |
| `make up-d`                      | Start in detached mode (runs migrations)             |
| `make down`                      | Stop containers                                      |
| `make down-v`                    | Stop containers and remove volumes                   |
| `make down-all`                  | Stop containers, remove volumes, images, and orphans |
| `make logs`                      | Tail container logs                                  |
| `make sh`                        | Shell into container                                 |
| `make format`                    | Format code with Ruff                                |
| `make lint`                      | Lint code with Ruff                                  |
| `make fix`                       | Auto-fix lint issues                                 |
| `make test`                      | Run tests                                            |
| `make test-cov`                  | Run tests with coverage report                       |
| `make test-cov-html`             | Run tests with HTML coverage report                  |
| `make migrate`                   | Run database migrations                              |
| `make migrate-new MSG="message"` | Create new migration                                 |
| `make migrate-down`              | Rollback last migration                              |
| `make migrate-history`           | Show migration history                               |

## Development

Hot reload is enabled—code changes reflect automatically without rebuilding.

### Adding Dependencies

```bash
# Shell into the container
make sh

# Add a package
poetry add <package-name>

# Add a dev dependency
poetry add --group dev <package-name>
```

## Project Structure

```
fastback/
├── app/
│   ├── main.py          # FastAPI application entry
│   ├── router.py        # Central router aggregation
│   ├── admin/           # SQLAdmin UI and authentication
│   ├── alembic/         # Database migrations
│   ├── core/            # Shared utilities (settings, deps, exceptions)
│   ├── db/              # Database engine and sessions
│   ├── models/          # Shared models
│   ├── templates/       # Email and other templates
│   └── <domain>/        # Domain modules (auth, user, health, etc.)
│       ├── router.py        # API endpoints
│       ├── service.py       # Business logic
│       ├── models.py        # Database models
│       ├── schemas.py       # Request/response Pydantic models
│       ├── dependencies.py  # Route dependencies
│       └── exceptions.py    # Domain-specific exceptions
├── tests/               # Pytest test suite
├── docs/                # Documentation
└── scripts/             # Utility scripts
```

Each domain module follows this convention. Not all files are required—include only what the domain needs.

## Exception Handling

FastBack uses a unified exception system with automatic HTTP status code mapping and consistent error response formatting.

### Exception System

All custom exceptions inherit from `AppException` and define their own `status_code` and `error_type`. Exceptions are automatically converted to JSON responses with the format:

```json
{
  "type": "error_type",
  "message": "Error message"
}
```

### Using Exceptions

Simply raise the appropriate exception in your route handlers or services:

```python
from app.core.exceptions import UserNotFoundError, EmailExistsError

@router.get("/user/{user_id}")
async def get_user(user_id: int, session: SessionDep):
    user = session.get(User, user_id)
    if not user:
        raise UserNotFoundError(f"User with ID {user_id} not found")
    return user
```

### Exception Types

#### Authentication Errors (401)

| Exception                 | Error Type             | Default Message                |
| ------------------------- | ---------------------- | ------------------------------ |
| `AuthenticationError`     | `authentication_error` | "Authentication failed"        |
| `InvalidCredentialsError` | `invalid_credentials`  | "Invalid email or password"    |
| `InvalidTokenError`       | `invalid_token`        | "Invalid authentication token" |
| `SessionCookieError`      | `session_cookie_error` | "Session cookie error"         |
| `SessionExpiredError`     | `session_expired`      | "Session has expired"          |

#### Authorization Errors (403)

| Exception            | Error Type            | Default Message            |
| -------------------- | --------------------- | -------------------------- |
| `AuthorizationError` | `authorization_error` | "Access denied"            |
| `UserDisabledError`  | `user_disabled`       | "User account is disabled" |
| `UserInactiveError`  | `user_inactive`       | "User is inactive"         |

#### Not Found Errors (404)

| Exception           | Error Type       | Default Message      |
| ------------------- | ---------------- | -------------------- |
| `NotFoundError`     | `not_found`      | "Resource not found" |
| `UserNotFoundError` | `user_not_found` | "User not found"     |

#### Conflict Errors (409)

| Exception          | Error Type     | Default Message            |
| ------------------ | -------------- | -------------------------- |
| `ConflictError`    | `conflict`     | "Resource conflict"        |
| `EmailExistsError` | `email_exists` | "Email already registered" |

#### Validation Errors (400)

| Exception                | Error Type                 | Default Message                       |
| ------------------------ | -------------------------- | ------------------------------------- |
| `ValidationError`        | `validation_error`         | "Validation failed"                   |
| `WeakPasswordError`      | `weak_password`            | "Password is too weak"                |
| `PasswordPolicyError`    | `password_policy_error`    | "Password does not meet requirements" |
| `BadRequestError`        | `bad_request`              | "Bad request"                         |
| `EmailVerificationError` | `email_verification_error` | "Email verification failed"           |

#### Rate Limit Errors (429)

| Exception        | Error Type            | Default Message                             |
| ---------------- | --------------------- | ------------------------------------------- |
| `RateLimitError` | `rate_limit_exceeded` | "Too many requests, please try again later" |

#### External Service Errors (502)

| Exception              | Error Type               | Default Message                                        |
| ---------------------- | ------------------------ | ------------------------------------------------------ |
| `ExternalServiceError` | `external_service_error` | "External service error"                               |
| `ProviderError`        | `provider_error`         | "Authentication provider returned an invalid response" |

#### Internal Errors (500)

| Exception       | Error Type       | Default Message              |
| --------------- | ---------------- | ---------------------------- |
| `InternalError` | `internal_error` | "An internal error occurred" |

### Custom Messages

All exceptions accept a custom message:

```python
from app.core.exceptions import UserNotFoundError

raise UserNotFoundError("Custom error message")
```

### Special Cases

`PasswordPolicyError` accepts an optional `requirements` parameter:

```python
from app.core.exceptions import PasswordPolicyError

raise PasswordPolicyError(
    message="Password validation failed",
    requirements=["Must be at least 8 characters", "Must contain uppercase"]
)
```

## Architecture & SOLID Principles

This project follows SOLID principles to maintain clean, maintainable code:

### Single Responsibility Principle (SRP)

Each module has one clear responsibility:

| Module                     | Responsibility                         |
| -------------------------- | -------------------------------------- |
| `app/auth/router.py`       | Authentication endpoints               |
| `app/auth/service.py`      | Firebase service abstraction           |
| `app/auth/dependencies.py` | Auth dependencies (CurrentUserDep)     |
| `app/user/router.py`       | User management endpoints              |
| `app/user/models.py`       | User database model                    |
| `app/router.py`            | Router aggregation only                |
| `app/db/engine.py`         | Database engine and session management |
| `app/core/settings.py`     | Typed application configuration        |
| `app/core/deps.py`         | Shared dependency providers            |
| `app/core/constants.py`    | Route prefixes and tags                |
| `app/core/firebase.py`     | Firebase SDK initialization            |
| `app/core/email.py`        | Email delivery via Resend              |
| `app/core/cors.py`         | CORS middleware configuration          |

### Open/Closed Principle (OCP)

- **Extensible routing**: Add new domain modules (e.g., `app/posts/`) with their own router and include it in `app/router.py`—no modification to existing route modules required
- **Model extension**: New models can be added without modifying existing ones

### Liskov Substitution Principle (LSP)

- SQLModel models extend `SQLModel` base class correctly
- Session dependencies can be mocked/substituted in tests

### Interface Segregation Principle (ISP)

- Route modules expose only a minimal `router` object
- `app/db` exports only what consumers need: `engine`, `get_session`
- `app/core/deps` provides focused dependency aliases: `SessionDep`, `SettingsDep`
- `app/auth/dependencies` provides auth-specific dependencies: `CurrentUserDep`, `AdminUserDep`, `FirebaseAuthDep`

### Dependency Inversion Principle (DIP)

- Routes depend on abstractions (`SessionDep`, `CurrentUserDep`, `SettingsDep`), not concrete implementations
- Configuration is loaded via Pydantic Settings with environment variable injection

### Using the Session Dependency

```python
from app.core.deps import SessionDep

@router.get("/items")
async def get_items(session: SessionDep):
    # session is automatically injected
    return session.exec(select(Item)).all()
```

### Using the CurrentUserDep Dependency

```python
from app.auth.dependencies import CurrentUserDep

@router.get("/me")
async def get_me(user: CurrentUserDep):
    # user is the authenticated User model from the database
    return {"id": user.id, "email": user.email}
```
