"""Retry utilities for async operations.

Provides exponential backoff retry logic for transient failures.
"""

import asyncio
from collections.abc import Awaitable, Callable

# Default retry configuration
DEFAULT_ATTEMPTS = 2
DEFAULT_BASE_DELAY = 0.2  # seconds


def _calculate_delay(attempt: int, base_delay: float = DEFAULT_BASE_DELAY) -> float:
    """Calculate exponential backoff delay for a given attempt.

    Args:
        attempt: Zero-indexed attempt number
        base_delay: Base delay in seconds

    Returns:
        Delay in seconds (base_delay * 2^attempt)
    """
    return base_delay * (2**attempt)


async def with_retry[T](
    fn: Callable[[], Awaitable[T]],
    attempts: int = DEFAULT_ATTEMPTS,
    exceptions: tuple[type[Exception], ...] = (Exception,),
    base_delay: float = DEFAULT_BASE_DELAY,
) -> T:
    """Execute async function with exponential backoff retry.

    Args:
        fn: Async function to execute (typically a lambda or partial)
        attempts: Maximum number of attempts
        exceptions: Tuple of exception types to catch and retry
        base_delay: Base delay in seconds for exponential backoff

    Returns:
        Result from successful function execution

    Raises:
        The last exception if all attempts fail

    Example:
        response = await with_retry(
            lambda: client.post(url, json=payload),
            attempts=3,
            exceptions=(httpx.RequestError,),
        )
    """
    last_error: Exception | None = None

    for attempt in range(attempts):
        try:
            return await fn()
        except exceptions as e:
            last_error = e
            if attempt < attempts - 1:
                delay = _calculate_delay(attempt, base_delay)
                await asyncio.sleep(delay)

    raise last_error  # type: ignore[misc]
