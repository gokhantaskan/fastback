"""HTTP client factory for external API calls.

Provides per-service HTTP clients with connection pooling, timeouts,
and proper resource management.
"""

from functools import lru_cache

import httpx

# Default timeout configuration (seconds)
DEFAULT_CONNECT_TIMEOUT = 5.0
DEFAULT_READ_TIMEOUT = 10.0
DEFAULT_WRITE_TIMEOUT = 10.0
DEFAULT_POOL_TIMEOUT = 5.0


def create_http_client(
    base_url: str = "",
    max_connections: int = 20,
    max_keepalive_connections: int = 10,
    connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
    read_timeout: float = DEFAULT_READ_TIMEOUT,
    write_timeout: float = DEFAULT_WRITE_TIMEOUT,
    pool_timeout: float = DEFAULT_POOL_TIMEOUT,
) -> httpx.AsyncClient:
    """Create a configured async HTTP client.

    Args:
        base_url: Base URL for all requests (empty string for none)
        max_connections: Maximum number of concurrent connections
        max_keepalive_connections: Maximum idle connections to keep alive
        connect_timeout: Timeout for establishing connection
        read_timeout: Timeout for reading response
        write_timeout: Timeout for sending request
        pool_timeout: Timeout for acquiring connection from pool

    Returns:
        Configured httpx.AsyncClient instance
    """
    return httpx.AsyncClient(
        base_url=base_url,
        timeout=httpx.Timeout(
            connect=connect_timeout,
            read=read_timeout,
            write=write_timeout,
            pool=pool_timeout,
        ),
        limits=httpx.Limits(
            max_connections=max_connections,
            max_keepalive_connections=max_keepalive_connections,
        ),
    )


@lru_cache
def get_firebase_client() -> httpx.AsyncClient:
    """Get cached HTTP client for Firebase Identity Toolkit.

    Tuned for high concurrency authentication requests.
    """
    return create_http_client(
        base_url="https://identitytoolkit.googleapis.com",
        max_connections=100,
        max_keepalive_connections=20,
    )
