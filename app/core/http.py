"""HTTP client factory for external API calls.

Provides per-service HTTP clients with connection pooling, timeouts,
and proper resource management.
"""

import httpx

# Default timeout configuration (seconds)
DEFAULT_CONNECT_TIMEOUT = 5.0
DEFAULT_READ_TIMEOUT = 10.0
DEFAULT_WRITE_TIMEOUT = 10.0
DEFAULT_POOL_TIMEOUT = 5.0

# Module-level client storage for singleton pattern
_firebase_client: httpx.AsyncClient | None = None


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


def get_firebase_client() -> httpx.AsyncClient:
    """Get singleton HTTP client for Firebase Identity Toolkit.

    Uses lazy initialization with module-level storage for proper
    resource management. The client should be closed via close_firebase_client()
    during application shutdown.

    Tuned for high concurrency authentication requests.

    Returns:
        Configured httpx.AsyncClient instance for Firebase API calls
    """
    global _firebase_client
    if _firebase_client is None:
        _firebase_client = create_http_client(
            base_url="https://identitytoolkit.googleapis.com",
            max_connections=100,
            max_keepalive_connections=20,
        )
    return _firebase_client


async def close_firebase_client() -> None:
    """Close the Firebase HTTP client and release resources.

    Should be called during application shutdown to properly close
    connections and release resources.
    """
    global _firebase_client
    if _firebase_client is not None:
        await _firebase_client.aclose()
        _firebase_client = None
