"""Tests for app/core/retry.py - Retry utilities."""

import pytest
from hypothesis import given
from hypothesis import settings as hypothesis_settings
from hypothesis import strategies as st

from app.core.retry import (
    DEFAULT_ATTEMPTS,
    DEFAULT_BASE_DELAY,
    _calculate_delay,
    with_retry,
)


class TestCalculateDelay:
    """Unit tests for _calculate_delay function."""

    def test_first_attempt_uses_base_delay(self):
        """Test that first attempt (0) returns base delay."""
        delay = _calculate_delay(0, base_delay=0.2)
        assert delay == 0.2

    def test_second_attempt_doubles_delay(self):
        """Test that second attempt (1) doubles the delay."""
        delay = _calculate_delay(1, base_delay=0.2)
        assert delay == 0.4

    def test_third_attempt_quadruples_delay(self):
        """Test that third attempt (2) quadruples the delay."""
        delay = _calculate_delay(2, base_delay=0.2)
        assert delay == 0.8

    def test_uses_default_base_delay(self):
        """Test that default base delay is used when not specified."""
        delay = _calculate_delay(0)
        assert delay == DEFAULT_BASE_DELAY

    @hypothesis_settings(max_examples=50)
    @given(
        attempt=st.integers(min_value=0, max_value=10),
        base_delay=st.floats(min_value=0.01, max_value=1.0),
    )
    def test_exponential_backoff_property(self, attempt, base_delay):
        """Property: delay = base_delay * 2^attempt."""
        delay = _calculate_delay(attempt, base_delay)
        expected = base_delay * (2**attempt)
        assert abs(delay - expected) < 1e-9


class TestWithRetry:
    """Unit tests for with_retry async function."""

    @pytest.mark.asyncio
    async def test_returns_result_on_first_success(self):
        """Test that result is returned immediately on success."""
        call_count = 0

        async def succeed():
            nonlocal call_count
            call_count += 1
            return "success"

        result = await with_retry(succeed)

        assert result == "success"
        assert call_count == 1

    @pytest.mark.asyncio
    async def test_retries_on_failure_then_succeeds(self):
        """Test that function retries on failure and succeeds."""
        call_count = 0

        async def fail_then_succeed():
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise ValueError("temporary error")
            return "success"

        result = await with_retry(
            fail_then_succeed,
            attempts=3,
            exceptions=(ValueError,),
            base_delay=0.01,
        )

        assert result == "success"
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_raises_after_all_attempts_exhausted(self):
        """Test that last exception is raised when all attempts fail."""
        call_count = 0

        async def always_fail():
            nonlocal call_count
            call_count += 1
            raise ValueError(f"error {call_count}")

        with pytest.raises(ValueError, match="error 3"):
            await with_retry(
                always_fail,
                attempts=3,
                exceptions=(ValueError,),
                base_delay=0.01,
            )

        assert call_count == 3

    @pytest.mark.asyncio
    async def test_does_not_catch_unspecified_exceptions(self):
        """Test that exceptions not in the tuple are not caught."""
        call_count = 0

        async def raise_type_error():
            nonlocal call_count
            call_count += 1
            raise TypeError("not catchable")

        with pytest.raises(TypeError, match="not catchable"):
            await with_retry(
                raise_type_error,
                attempts=3,
                exceptions=(ValueError,),
                base_delay=0.01,
            )

        # Should fail on first attempt since TypeError is not caught
        assert call_count == 1

    @pytest.mark.asyncio
    async def test_uses_default_attempts(self):
        """Test that default attempts value is used."""
        call_count = 0

        async def always_fail():
            nonlocal call_count
            call_count += 1
            raise ValueError("error")

        with pytest.raises(ValueError):
            await with_retry(always_fail, exceptions=(ValueError,), base_delay=0.01)

        assert call_count == DEFAULT_ATTEMPTS

    @pytest.mark.asyncio
    async def test_catches_multiple_exception_types(self):
        """Test that multiple exception types can be caught."""
        call_count = 0

        async def alternate_errors():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise ValueError("value error")
            if call_count == 2:
                raise TypeError("type error")
            return "success"

        result = await with_retry(
            alternate_errors,
            attempts=3,
            exceptions=(ValueError, TypeError),
            base_delay=0.01,
        )

        assert result == "success"
        assert call_count == 3
