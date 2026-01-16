"""Tests for app/core/cors.py - CORS middleware configuration."""

from unittest.mock import MagicMock

from app.core.cors import add_cors_middleware
from app.core.settings import get_settings


def test_add_cors_middleware():
    """Test add_cors_middleware() adds CORS with correct configuration."""
    mock_app = MagicMock()
    settings = get_settings()

    add_cors_middleware(mock_app)

    mock_app.add_middleware.assert_called_once()
    call_kwargs = mock_app.add_middleware.call_args[1]
    assert call_kwargs["allow_origins"] == settings.cors_origins_list
    assert call_kwargs["allow_credentials"] is True
    assert call_kwargs["allow_methods"] == ["*"]
    assert call_kwargs["allow_headers"] == ["*"]


def test_cors_origins_list_parsing():
    """Test that Settings.cors_origins_list correctly parses CORS origins."""
    settings = get_settings()

    # The cors_origins_list property should return a list
    assert isinstance(settings.cors_origins_list, list)

    # Each origin should be non-empty string
    for origin in settings.cors_origins_list:
        assert isinstance(origin, str)
        assert origin.strip() == origin  # No leading/trailing whitespace
        assert len(origin) > 0
