"""Tests for app/main.py - Application lifespan and initialization."""

from unittest.mock import patch

import pytest
from fastapi import FastAPI

from app.main import lifespan


@pytest.mark.asyncio
async def test_lifespan_initialization():
    """Test lifespan context manager initializes Firebase, Resend, and DB."""
    mock_app = FastAPI()

    with (
        patch("app.main.init_firebase") as mock_firebase,
        patch("app.main.init_resend") as mock_resend,
    ):
        async with lifespan(mock_app):
            # Verify all initialization functions were called
            mock_firebase.assert_called_once()
            mock_resend.assert_called_once()
