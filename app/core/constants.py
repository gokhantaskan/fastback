"""
App-wide constants for route configuration.

This module provides a single source of truth for route prefixes, tags,
and common response definitions for API routes.
"""

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class RouteConfig:
    """Configuration for a route group."""

    prefix: str
    tag: str


class Routes:
    """Route configurations for all API endpoints."""

    AUTH = RouteConfig(prefix="/auth", tag="auth")
    USER = RouteConfig(prefix="/user", tag="user")
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
