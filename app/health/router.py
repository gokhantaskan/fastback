"""Health domain router.

Health check endpoint for monitoring and load balancers.
"""

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.core.constants import Routes
from app.core.deps import SessionDep

router = APIRouter(prefix=Routes.HEALTH.prefix, tags=[Routes.HEALTH.tag])


@router.get("")
async def health(session: SessionDep):
    """Health check endpoint with database connectivity verification."""
    try:
        session.exec(text("SELECT 1"))
        return {"status": "ok", "database": "ok"}
    except Exception:
        return JSONResponse(
            status_code=503,
            content={"status": "unhealthy", "database": "error"},
        )
