"""Error response schemas for consistent API error formatting."""

from pydantic import BaseModel


class ErrorResponse(BaseModel):
    """Standard error response schema.

    All API errors return this format for consistency.
    """

    type: str
    message: str
