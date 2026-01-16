"""
Model package.

IMPORTANT (Alembic / SQLModel):
- Alembic autogenerate relies on `SQLModel.metadata`, which is populated only
  when the table models are imported.
- `alembic/env.py` imports `app.models`, so this module must import all
  SQLModel `table=True` models to register them.
"""

# Import table models so SQLModel registers them in metadata.
from app.user.models import User  # noqa: F401
