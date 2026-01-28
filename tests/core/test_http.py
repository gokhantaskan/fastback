"""Tests for app/core/http.py - HTTP client factory."""

import httpx

from app.core.http import (
    DEFAULT_CONNECT_TIMEOUT,
    DEFAULT_POOL_TIMEOUT,
    DEFAULT_READ_TIMEOUT,
    DEFAULT_WRITE_TIMEOUT,
    create_http_client,
    get_firebase_client,
)


class TestCreateHttpClient:
    """Unit tests for create_http_client factory."""

    def test_returns_async_client(self):
        """Test that factory returns an httpx.AsyncClient instance."""
        client = create_http_client(base_url="https://example.com")
        assert isinstance(client, httpx.AsyncClient)

    def test_default_timeouts(self):
        """Test that default timeout values are applied."""
        client = create_http_client(base_url="https://example.com")
        timeout = client.timeout

        assert timeout.connect == DEFAULT_CONNECT_TIMEOUT
        assert timeout.read == DEFAULT_READ_TIMEOUT
        assert timeout.write == DEFAULT_WRITE_TIMEOUT
        assert timeout.pool == DEFAULT_POOL_TIMEOUT

    def test_custom_timeouts(self):
        """Test that custom timeout values are applied."""
        client = create_http_client(
            base_url="https://example.com",
            connect_timeout=1.0,
            read_timeout=2.0,
            write_timeout=3.0,
            pool_timeout=4.0,
        )
        timeout = client.timeout

        assert timeout.connect == 1.0
        assert timeout.read == 2.0
        assert timeout.write == 3.0
        assert timeout.pool == 4.0

    def test_default_connection_limits(self):
        """Test that default connection limits are applied."""
        client = create_http_client(base_url="https://example.com")
        limits = client._transport._pool._max_connections  # type: ignore[union-attr]

        assert limits == 20

    def test_custom_connection_limits(self):
        """Test that custom connection limits are applied."""
        client = create_http_client(
            base_url="https://example.com",
            max_connections=50,
            max_keepalive_connections=25,
        )
        limits = client._transport._pool._max_connections  # type: ignore[union-attr]

        assert limits == 50

    def test_empty_base_url_by_default(self):
        """Test that base_url defaults to empty string."""
        client = create_http_client()
        assert client.base_url == httpx.URL("")

    def test_custom_base_url(self):
        """Test that custom base_url is applied."""
        client = create_http_client(base_url="https://api.example.com")
        assert client.base_url == httpx.URL("https://api.example.com")


class TestGetFirebaseClient:
    """Unit tests for get_firebase_client cached getter."""

    def test_returns_async_client(self):
        """Test that getter returns an httpx.AsyncClient instance."""
        # Clear the cache to ensure fresh client
        get_firebase_client.cache_clear()

        client = get_firebase_client()
        assert isinstance(client, httpx.AsyncClient)

    def test_has_firebase_base_url(self):
        """Test that Firebase client has correct base URL."""
        get_firebase_client.cache_clear()

        client = get_firebase_client()
        assert client.base_url == httpx.URL("https://identitytoolkit.googleapis.com")

    def test_has_high_concurrency_limits(self):
        """Test that Firebase client is configured for high concurrency."""
        get_firebase_client.cache_clear()

        client = get_firebase_client()
        limits = client._transport._pool._max_connections  # type: ignore[union-attr]

        assert limits == 100

    def test_is_cached(self):
        """Test that get_firebase_client returns the same instance."""
        get_firebase_client.cache_clear()

        client1 = get_firebase_client()
        client2 = get_firebase_client()

        assert client1 is client2
