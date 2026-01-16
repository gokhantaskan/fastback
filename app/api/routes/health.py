from fastapi import APIRouter

from app.core.constants import Routes

router = APIRouter(prefix=Routes.HEALTH.prefix, tags=[Routes.HEALTH.tag])


@router.get("")
async def health():
    return {"status": "ok"}
