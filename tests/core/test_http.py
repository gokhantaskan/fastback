"""Tests for app/core/http.py - HTTP client factory."""

import anyio
import httpx
import pytest

from app.core import http as http_module


async def _close_and_reset_firebase_client_async() -> None:
    """Close and reset the Firebase client singleton (async implementation)."""
    if http_module._firebase_client is not None:
        await http_module._firebase_client.aclose()
    http_module._firebase_client = None


def _close_and_reset_firebase_client() -> None:
    """Close and reset the Firebase client singleton (for test cleanup)."""
    anyio.run(_close_and_reset_firebase_client_async)


class TestCreateHttpClient:
    """Unit tests for create_http_client factory."""

    @pytest.mark.asyncio
    async def test_returns_async_client(self):
        """Test that factory returns an httpx.AsyncClient instance."""
        client = http_module.create_http_client(base_url="https://example.com")
        try:
            assert isinstance(client, httpx.AsyncClient)
        finally:
            await client.aclose()

    @pytest.mark.asyncio
    async def test_default_timeouts(self):
        """Test that default timeout values are applied."""
        client = http_module.create_http_client(base_url="https://example.com")
        try:
            timeout = client.timeout

            assert timeout.connect == http_module.DEFAULT_CONNECT_TIMEOUT
            assert timeout.read == http_module.DEFAULT_READ_TIMEOUT
            assert timeout.write == http_module.DEFAULT_WRITE_TIMEOUT
            assert timeout.pool == http_module.DEFAULT_POOL_TIMEOUT
        finally:
            await client.aclose()

    @pytest.mark.asyncio
    async def test_custom_timeouts(self):
        """Test that custom timeout values are applied."""
        client = http_module.create_http_client(
            base_url="https://example.com",
            connect_timeout=1.0,
            read_timeout=2.0,
            write_timeout=3.0,
            pool_timeout=4.0,
        )
        try:
            timeout = client.timeout

            assert timeout.connect == 1.0
            assert timeout.read == 2.0
            assert timeout.write == 3.0
            assert timeout.pool == 4.0
        finally:
            await client.aclose()

    @pytest.mark.asyncio
    async def test_default_connection_limits(self):
        """Test that default connection limits are applied."""
        client = http_module.create_http_client(base_url="https://example.com")
        try:
            limits = client._transport._pool._max_connections  # type: ignore[union-attr]

            assert limits == 20
        finally:
            await client.aclose()

    @pytest.mark.asyncio
    async def test_custom_connection_limits(self):
        """Test that custom connection limits are applied."""
        client = http_module.create_http_client(
            base_url="https://example.com",
            max_connections=50,
            max_keepalive_connections=25,
        )
        try:
            limits = client._transport._pool._max_connections  # type: ignore[union-attr]

            assert limits == 50
        finally:
            await client.aclose()

    @pytest.mark.asyncio
    async def test_empty_base_url_by_default(self):
        """Test that base_url defaults to empty string."""
        client = http_module.create_http_client()
        try:
            assert client.base_url == httpx.URL("")
        finally:
            await client.aclose()

    @pytest.mark.asyncio
    async def test_custom_base_url(self):
        """Test that custom base_url is applied."""
        client = http_module.create_http_client(base_url="https://api.example.com")
        try:
            assert client.base_url == httpx.URL("https://api.example.com")
        finally:
            await client.aclose()


class TestGetFirebaseClient:
    """Unit tests for get_firebase_client singleton getter."""

    @pytest.fixture(autouse=True)
    def reset_firebase_client(self):
        """Reset the Firebase client singleton before and after each test."""
        _close_and_reset_firebase_client()
        yield
        _close_and_reset_firebase_client()

    @pytest.mark.asyncio
    async def test_returns_async_client(self):
        """Test that getter returns an httpx.AsyncClient instance."""
        client = http_module.get_firebase_client()
        assert isinstance(client, httpx.AsyncClient)

    @pytest.mark.asyncio
    async def test_has_firebase_base_url(self):
        """Test that Firebase client has correct base URL."""
        client = http_module.get_firebase_client()
        assert client.base_url == httpx.URL("https://identitytoolkit.googleapis.com")

    @pytest.mark.asyncio
    async def test_has_high_concurrency_limits(self):
        """Test that Firebase client is configured for high concurrency."""
        client = http_module.get_firebase_client()
        limits = client._transport._pool._max_connections  # type: ignore[union-attr]

        assert limits == 100

    @pytest.mark.asyncio
    async def test_is_singleton(self):
        """Test that get_firebase_client returns the same instance."""
        client1 = http_module.get_firebase_client()
        client2 = http_module.get_firebase_client()

        assert client1 is client2


class TestCloseFirebaseClient:
    """Unit tests for close_firebase_client cleanup function."""

    @pytest.fixture(autouse=True)
    def reset_firebase_client(self):
        """Reset the Firebase client singleton before and after each test."""
        _close_and_reset_firebase_client()
        yield
        _close_and_reset_firebase_client()

    @pytest.mark.asyncio
    async def test_closes_client(self):
        """Test that close_firebase_client closes the client."""
        client = http_module.get_firebase_client()
        assert not client.is_closed

        await http_module.close_firebase_client()

        assert client.is_closed

    @pytest.mark.asyncio
    async def test_resets_singleton(self):
        """Test that close_firebase_client resets the module-level variable."""
        http_module.get_firebase_client()
        assert http_module._firebase_client is not None

        await http_module.close_firebase_client()

        assert http_module._firebase_client is None

    @pytest.mark.asyncio
    async def test_safe_to_call_when_no_client(self):
        """Test that close_firebase_client is safe to call when no client exists."""
        assert http_module._firebase_client is None

        # Should not raise
        await http_module.close_firebase_client()

        assert http_module._firebase_client is None

    @pytest.mark.asyncio
    async def test_creates_new_client_after_close(self):
        """Test that a new client is created after closing."""
        client1 = http_module.get_firebase_client()
        await http_module.close_firebase_client()

        client2 = http_module.get_firebase_client()

        assert client1 is not client2
        assert not client2.is_closed
