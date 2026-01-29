from contextlib import asynccontextmanager

from fastapi import APIRouter, FastAPI
from sqladmin import Admin

from app.admin.auth import AdminAuth
from app.admin.views import UserAdmin
from app.auth.router import router as auth_router
from app.core.cors import add_cors_middleware
from app.core.email import init_resend
from app.core.exception_handlers import register_exception_handlers
from app.core.firebase import init_firebase
from app.core.logging import configure_logging
from app.core.request_logging import add_request_logging_middleware
from app.db.engine import engine
from app.health.router import router as health_router
from app.user.router import router as user_router

configure_logging()


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_firebase()
    init_resend()
    yield
    # Cleanup HTTP clients
    from app.core.http import close_firebase_client

    await close_firebase_client()


app = FastAPI(title="FastBack", version="0.1.0", lifespan=lifespan)

api_router = APIRouter()
api_router.include_router(health_router)
api_router.include_router(auth_router)
api_router.include_router(user_router)

app.include_router(api_router)

add_request_logging_middleware(app)
add_cors_middleware(app)
register_exception_handlers(app)

# Mount SQLAdmin UI at /admin (SQLAdmin enables sessions via auth backend secret)
admin = Admin(
    app=app,
    engine=engine,
    authentication_backend=AdminAuth(),
)
admin.add_view(UserAdmin)
