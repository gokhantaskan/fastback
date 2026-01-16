---
name: solidprinciples
description: SOLID Principles for Python and FastAPI project
---

## Architecture & SOLID Principles

This project follows SOLID principles to maintain clean, maintainable code:

### Single Responsibility Principle (SRP)

Each module has one clear responsibility:

| Module                     | Responsibility                         |
| -------------------------- | -------------------------------------- |
| `app/api/routes/*.py`      | HTTP endpoint handlers                 |
| `app/api/router.py`        | Router aggregation only                |
| `app/db/engine.py`         | Database engine and session management |
| `app/core/settings.py`     | Application configuration              |
| `app/core/dependencies.py` | Dependency injection providers         |
| `app/services/*.py`        | Business logic services                |
| `app/models/*.py`          | Data models and validation             |

### Open/Closed Principle (OCP)

- **Extensible routing**: Add new routes by creating a module in `app/api/routes/` and including it in `router.py`—no modification to existing route modules required
- **Model extension**: New models can be added without modifying existing ones

### Liskov Substitution Principle (LSP)

- SQLModel models extend `SQLModel` base class correctly
- Session dependencies can be mocked/substituted in tests

### Interface Segregation Principle (ISP)

- Route modules expose only a minimal `router` object
- `app/db` exports only what consumers need: `SessionDep`, `get_session`
- `app/core/dependencies` provides focused dependency aliases: `SettingsDep`, `FirebaseAuthDep`

### Dependency Inversion Principle (DIP)

- Routes depend on abstractions (`SessionDep`, `CurrentUser`, `SettingsDep`), not concrete implementations
- Configuration is injected via Pydantic Settings with environment variables

### Example: Using Dependencies

```python
from app.db import SessionDep
from app.core.auth import CurrentUser

@router.get("/items")
async def get_items(session: SessionDep):
    return session.exec(select(Item)).all()

@router.get("/me")
async def get_me(user: CurrentUser):
    return {"id": user.id, "email": user.email}
```
