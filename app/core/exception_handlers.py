"""Global exception handlers for consistent error responses.

This module registers exception handlers that convert all exceptions
to a unified JSON response format.
"""

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.exceptions import AppException

logger = logging.getLogger("app.exception")


def app_exception_handler(request: Request, exc: AppException) -> JSONResponse:
    """Handle all AppException subclasses."""
    extra = {
        "method": request.method,
        "path": request.url.path,
        "status_code": exc.status_code,
        "error_type": exc.error_type,
    }
    if exc.status_code >= 500:
        logger.error("AppException: %s - %s", exc.error_type, exc.message, extra=extra)
    else:
        logger.info("AppException: %s - %s", exc.error_type, exc.message, extra=extra)
    return JSONResponse(
        status_code=exc.status_code,
        content={"type": exc.error_type, "message": exc.message},
    )


def http_exception_handler(
    _request: Request, exc: StarletteHTTPException
) -> JSONResponse:
    """Handle HTTPException for backwards compatibility."""
    return JSONResponse(
        status_code=exc.status_code,
        content={"type": "http_error", "message": str(exc.detail)},
    )


def validation_exception_handler(
    _request: Request, exc: RequestValidationError
) -> JSONResponse:
    """Handle Pydantic validation errors with unified format."""
    errors = exc.errors()
    if len(errors) == 1:
        error = errors[0]
        field = ".".join(str(loc) for loc in error["loc"] if loc != "body")
        message = f"{field}: {error['msg']}" if field else error["msg"]
    else:
        messages = []
        for error in errors:
            field = ".".join(str(loc) for loc in error["loc"] if loc != "body")
            messages.append(f"{field}: {error['msg']}" if field else error["msg"])
        message = "; ".join(messages)

    return JSONResponse(
        status_code=422,
        content={"type": "validation_error", "message": message},
    )


def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catch-all handler for unexpected errors."""
    logger.error(
        "Unhandled exception: %s %s - %s",
        request.method,
        request.url.path,
        exc,
        extra={"method": request.method, "path": request.url.path, "status_code": 500},
        exc_info=True,
    )
    return JSONResponse(
        status_code=500,
        content={"type": "internal_error", "message": "An unexpected error occurred"},
    )


def register_exception_handlers(app: FastAPI) -> None:
    """Register all exception handlers with the FastAPI app."""
    app.add_exception_handler(AppException, app_exception_handler)
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(Exception, unhandled_exception_handler)
