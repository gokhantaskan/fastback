from contextlib import asynccontextmanager

from fastapi import FastAPI
from sqladmin import Admin

from app.admin.auth import AdminAuth
from app.admin.views import UserAdmin
from app.core.cors import add_cors_middleware
from app.core.email import init_resend
from app.core.exception_handlers import register_exception_handlers
from app.core.firebase import init_firebase
from app.core.logging import configure_logging
from app.core.request_logging import add_request_logging_middleware
from app.db.engine import engine
from app.router import api_router

configure_logging()


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_firebase()
    init_resend()
    yield


app = FastAPI(title="FastBack", version="0.1.0", lifespan=lifespan)
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
