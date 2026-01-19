"""Reusable model mixins.

Provides common field patterns for SQLModel table definitions.
"""

from datetime import UTC, datetime

from sqlalchemy import text
from sqlmodel import Field


def _utc_now() -> datetime:
    """Return current UTC time without microseconds."""
    return datetime.now(UTC).replace(microsecond=0)


class TimestampMixin:
    """Mixin that adds created_at and updated_at timestamps.

    Timestamps are stored without microseconds for cleaner output.

    Usage:
        class MyModel(TimestampMixin, SQLModel, table=True):
            id: int = Field(primary_key=True)
            name: str
    """

    created_at: datetime = Field(
        default_factory=_utc_now,
        sa_column_kwargs={"server_default": text("CURRENT_TIMESTAMP")},
    )
    updated_at: datetime = Field(
        default_factory=_utc_now,
        sa_column_kwargs={
            "server_default": text("CURRENT_TIMESTAMP"),
            "onupdate": _utc_now,
        },
    )
