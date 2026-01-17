"""Health domain router.

Health check endpoint for monitoring and load balancers.
"""

from fastapi import APIRouter

from app.core.constants import Routes

router = APIRouter(prefix=Routes.HEALTH.prefix, tags=[Routes.HEALTH.tag])


@router.get("")
async def health():
    """Health check endpoint."""
    return {"status": "ok"}
