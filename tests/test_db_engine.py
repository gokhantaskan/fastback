"""Tests for app/db/engine.py - Database engine and session management."""

import contextlib

from app.db.engine import get_session


def test_get_session():
    """Test get_session() yields a database session."""
    gen = get_session()
    session = next(gen)

    # Verify we got a session object
    assert session is not None

    # Clean up - complete the generator
    with contextlib.suppress(StopIteration):
        next(gen)
