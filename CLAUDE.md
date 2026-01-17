# FastAPI Best Practices: AI Agent Guide

Concise but complete reference for AI agents building production-grade FastAPI applications.
This guide fully encompasses and distills proven FastAPI best practices used in large-scale systems.

## Project Structure

Use domain-based organization for scalability and long-term maintainability.

```
src/
├── auth/
│   ├── router.py        # Endpoints
│   ├── schemas.py       # Pydantic models
│   ├── models.py        # DB models
│   ├── service.py       # Business logic
│   ├── dependencies.py  # Route dependencies
│   ├── exceptions.py    # Domain exceptions
│   ├── constants.py     # Error codes, constants
│   ├── utils.py         # Non-business helpers
│   └── config.py        # Domain settings
├── posts/
│   └── ...
├── config.py            # Global config
├── database.py          # DB connection
├── exceptions.py        # Global exceptions
├── pagination.py        # Shared utilities
└── main.py              # App initialization
```

### Cross-module imports

Cross-module imports must be explicit:

**✅ DO**

```python
from src.auth import constants as auth_constants
from src.notifications import service as notification_service
```

**❌ DON'T**

```python
from src.auth.constants import *
```

## Async Routes

FastAPI is async-first.
Incorrect async usage can block the entire server.

**❌ DON'T: blocks the event loop**

```python
@router.get("/bad")
async def bad():
    time.sleep(10)
```

**✅ DO: sync route runs in threadpool**

```python
@router.get("/ok")
def ok():
    time.sleep(10)
```

**✅ DO: proper async**

```python
@router.get("/best")
async def best():
    await asyncio.sleep(10)
```

### Task Type Decision Table

| Task Type              | Correct Approach                 |
| ---------------------- | -------------------------------- |
| I/O with async library | async def + await                |
| I/O with sync library  | def route OR run_in_threadpool() |
| CPU-intensive          | Celery / multiprocessing         |

⚠ Threadpools are bounded and expensive.
Overuse can exhaust workers and degrade performance.

### CPU-Intensive Work

- Async provides no benefit for CPU-heavy tasks
- Threads are ineffective due to the GIL
- Offload CPU work to:
  - Celery
  - multiprocessing
  - external workers

## Pydantic

Use Pydantic aggressively for validation and transformation.

```python
class UserCreate(BaseModel):
    username: str = Field(
        min_length=1,
        max_length=128,
        pattern="^[A-Za-z0-9-_]+$"
    )
    email: EmailStr
    age: int = Field(ge=18)
```

### Custom Base Model (Recommended)

Create a global base model for shared behavior:

- datetime formatting
- serialization helpers
- config defaults

```python
class CustomModel(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True
    )
```

### Configuration (BaseSettings)

❌ One giant settings class  
✅ Split settings by domain

## Dependencies

Use dependencies for validation beyond schemas:

- database existence checks
- authentication
- authorization and ownership logic

```python
async def valid_post_id(post_id: UUID4) -> dict:
    post = await service.get_by_id(post_id)
    if not post:
        raise PostNotFound()
    return post

@router.get("/posts/{post_id}")
async def get_post(
    post: dict = Depends(valid_post_id)
):
    return post
```

### Chain Dependencies (Cached Per Request)

```python
async def valid_owned_post(
    post: dict = Depends(valid_post_id),
    token: dict = Depends(parse_jwt_data),
):
    if post["creator_id"] != token["user_id"]:
        raise UserNotOwner()
    return post
```

Prefer async dependencies.
Sync dependencies run in the threadpool and add overhead.

## REST Conventions

Use consistent path parameter names to enable dependency reuse.

**✅ DO**

```python
@router.get("/profiles/{profile_id}")
@router.get("/creators/{profile_id}")
```

**❌ DON'T**

```python
@router.get("/creators/{creator_id}")
```

## FastAPI Response Serialization

Returning a Pydantic model does not skip validation.

FastAPI performs:

1. jsonable_encoder conversion
2. response_model validation
3. JSON serialization

Response models are often constructed twice.
Avoid heavy logic in response validators.

## Sync Libraries in Async Routes

Use run_in_threadpool when calling sync code from async routes.

```python
from fastapi.concurrency import run_in_threadpool

@router.get("/")
async def call_sync():
    result = await run_in_threadpool(
        sync_client.request,
        data=my_data
    )
    return result
```

## Validation Errors & Security

Raising ValueError inside Pydantic validators used in request bodies
will surface detailed error messages to users.

Be intentional.
This can leak validation rules or internal logic.

## Documentation (OpenAPI)

Hide docs by default for non-public APIs.

```python
if ENVIRONMENT not in ("local", "staging"):
    app = FastAPI(openapi_url=None)
```

Improve docs quality:

- always set response_model
- define status_code
- add summary and description
- use responses for multiple outcomes

## Database Best Practices

SQL-first, Pydantic-second:

- perform joins and aggregations in SQL
- avoid Python loops and N+1 queries
- return ready-to-serialize data

### Naming conventions

- lower_case_snake
- singular table names
- `_at` for datetime
- `_date` for date

Set explicit index and constraint naming conventions.

### Migrations (Alembic)

- migrations must be static and reversible
- use descriptive slugs
- prefer human-readable filenames

Example:
`2024-01-15_add_post_slug_index.py`

## Testing

Use an async test client from day one.

```python
@pytest.fixture
async def client():
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test"
    ) as c:
        yield c
```

## Quick Reference

| Category     | ✅ DO              | ❌ DON'T             |
| ------------ | ------------------ | -------------------- |
| Async        | async def + await  | Blocking calls       |
| Sync I/O     | def or threadpool  | Sync calls in async  |
| CPU work     | Celery / processes | Threads              |
| Dependencies | Chain and reuse    | Duplicate validation |
| Config       | Split by domain    | One giant class      |
| Imports      | Explicit modules   | Wildcards            |
| DB           | SQL joins          | Python loops         |
| Responses    | Lightweight models | Heavy validators     |
| Tests        | Async from start   | Retrofit async later |

## Principle

FastAPI is fast only if you respect async semantics,
dependency design, and database boundaries.
