"""
App-wide constants for route configuration.

This module provides a single source of truth for route prefixes, tags,
and common response definitions for API routes.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape


@dataclass(frozen=True)
class RouteConfig:
    """Configuration for a route group."""

    prefix: str
    tag: str


class Routes:
    """Route configurations for all API endpoints."""

    AUTH = RouteConfig(prefix="/auth", tag="auth")
    USER = RouteConfig(prefix="/users", tag="users")
    HEALTH = RouteConfig(prefix="/health", tag="health")


# Common response definitions for reuse across routers
# Use these when configuring APIRouter or individual endpoints
class CommonResponses:
    """Standard HTTP error response definitions for OpenAPI documentation."""

    UNAUTHORIZED: dict[int, dict[str, Any]] = {
        401: {"description": "Not authenticated or invalid credentials"}
    }
    FORBIDDEN: dict[int, dict[str, Any]] = {
        403: {"description": "User is inactive or lacks permissions"}
    }
    NOT_FOUND: dict[int, dict[str, Any]] = {404: {"description": "Resource not found"}}
    CONFLICT: dict[int, dict[str, Any]] = {
        409: {"description": "Resource already exists"}
    }
    BAD_REQUEST: dict[int, dict[str, Any]] = {
        400: {"description": "Invalid request data"}
    }


# HTML Templates Directory
EmailTemplatesDir = Path(__file__).parent.parent / "templates" / "emails"
CompiledEmailTemplatesDir = EmailTemplatesDir / "compiled"

# Jinja2 environment for source templates (used by compile script)
JinjaEmailTemplatesEnv = Environment(
    loader=FileSystemLoader(str(EmailTemplatesDir)),
    autoescape=select_autoescape(["html", "xml"]),
)

# Jinja2 environment for compiled templates (used at runtime)
JinjaCompiledEmailTemplatesEnv = Environment(
    loader=FileSystemLoader(str(CompiledEmailTemplatesDir)),
    autoescape=select_autoescape(["html", "xml"]),
)
