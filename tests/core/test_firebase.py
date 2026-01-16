"""Tests for app/core/firebase.py - Firebase initialization."""

from unittest.mock import patch

from app.core.firebase import init_firebase


def test_init_firebase_already_initialized():
    """Test init_firebase() does nothing if Firebase already initialized."""
    with (
        patch("app.core.firebase.get_app") as mock_get_app,
        patch("app.core.firebase.initialize_app") as mock_init,
    ):
        # get_app() succeeds, meaning Firebase is already initialized
        mock_get_app.return_value = "mock_app"

        init_firebase()

        mock_get_app.assert_called_once()
        mock_init.assert_not_called()


def test_init_firebase_not_initialized():
    """Test init_firebase() initializes Firebase if not already initialized."""
    with (
        patch("app.core.firebase.get_app") as mock_get_app,
        patch("app.core.firebase.initialize_app") as mock_init,
    ):
        # get_app() raises ValueError, meaning Firebase is not initialized
        mock_get_app.side_effect = ValueError("Firebase app not initialized")

        init_firebase()

        mock_get_app.assert_called_once()
        mock_init.assert_called_once()
