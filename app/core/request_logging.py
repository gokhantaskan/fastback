"""HTTP request/response logging middleware."""

from __future__ import annotations

import logging
import os
import time
from typing import Any

from fastapi import FastAPI
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response


def _env_bool(name: str, *, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "t", "yes", "y", "on"}


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: FastAPI) -> None:
        super().__init__(app)
        self.logger = logging.getLogger("app.request")

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        start = time.perf_counter()
        response: Response | None = None
        try:
            response = await call_next(request)
            return response
        finally:
            duration_ms = (time.perf_counter() - start) * 1000.0

            status_code: int | None = response.status_code if response else None
            client_ip = request.client.host if request.client else None
            user_agent = request.headers.get("user-agent")

            extra: dict[str, Any] = {
                "method": request.method,
                "path": request.url.path,
                "query": request.url.query,
                "status_code": status_code,
                "duration_ms": round(duration_ms, 2),
                "client_ip": client_ip,
                "user_agent": user_agent,
            }

            if status_code is None or status_code >= 500:
                log = self.logger.error
            else:
                log = self.logger.info

            log(
                "%s %s%s -> %s (%.2fms)",
                request.method,
                request.url.path,
                f"?{request.url.query}" if request.url.query else "",
                status_code,
                duration_ms,
                extra=extra,
            )


def add_request_logging_middleware(app: FastAPI) -> None:
    """Attach request logging middleware (enabled by default)."""

    if not _env_bool("LOG_REQUESTS", default=True):
        return
    app.add_middleware(RequestLoggingMiddleware)
