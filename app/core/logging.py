"""Central logging configuration for the application.

Keeps logs Docker-friendly (stdout) and integrates with Uvicorn/FastAPI.
Configuration is driven by environment variables so it works even when
typed Settings are not available (e.g. during early imports).
"""

from __future__ import annotations

import json
import logging
import logging.config
import os
import sys
from datetime import UTC, datetime
from typing import Any


def _env_bool(name: str, *, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "t", "yes", "y", "on"}


class JsonFormatter(logging.Formatter):
    """Minimal JSON formatter (no external deps)."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }

        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)

        # Common extras we might attach from middleware / handlers.
        extras = record.__dict__
        for key in (
            "method",
            "path",
            "query",
            "status_code",
            "duration_ms",
            "client_ip",
            "user_agent",
            "error_type",
        ):
            if key in extras:
                payload[key] = extras[key]

        return json.dumps(payload, ensure_ascii=False)


def configure_logging() -> None:
    """Configure stdlib logging for app + uvicorn.

    Env vars:
    - LOG_LEVEL: DEBUG|INFO|WARNING|ERROR (default: INFO)
    - LOG_JSON: true/false (default: false)
    - LOG_REQUESTS: true/false (default: true)
    - LOG_UVICORN_ACCESS: true/false
        - if unset: defaults to false when LOG_REQUESTS=true (avoid duplicate logs),
          otherwise true.
    """

    level = os.getenv("LOG_LEVEL", "INFO").upper()
    log_json = _env_bool("LOG_JSON", default=False)
    log_requests = _env_bool("LOG_REQUESTS", default=True)
    uvicorn_access = _env_bool(
        "LOG_UVICORN_ACCESS",
        default=not log_requests,
    )

    formatter_name = "json" if log_json else "text"

    config: dict[str, Any] = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "text": {
                "format": "%(asctime)s | %(levelname)s | %(name)s | %(message)s",
            },
            "json": {
                "()": "app.core.logging.JsonFormatter",
            },
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "level": level,
                "formatter": formatter_name,
                "stream": sys.stdout,
            }
        },
        "root": {"handlers": ["console"], "level": level},
        "loggers": {
            # Uvicorn manages these loggers; we route them into our root handler.
            "uvicorn": {"level": level, "propagate": True},
            "uvicorn.error": {"level": level, "propagate": True},
            "uvicorn.access": {
                "level": "INFO" if uvicorn_access else "WARNING",
                "propagate": True,
            },
            # Keep noisy libs reasonable by default.
            "httpx": {
                "level": os.getenv("HTTPX_LOG_LEVEL", "WARNING"),
                "propagate": True,
            },
        },
    }

    logging.config.dictConfig(config)
