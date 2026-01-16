from sqladmin.authentication import AuthenticationBackend
from starlette.requests import Request

from app.core.settings import get_settings


class AdminAuth(AuthenticationBackend):
    """SQLAdmin auth using Starlette sessions."""

    def __init__(self) -> None:
        # SQLAdmin uses this secret internally (e.g. login form protection).
        # It must be stable and should match the session middleware secret.
        settings = get_settings()
        super().__init__(secret_key=settings.session_secret_key)

    async def login(self, request: Request) -> bool:
        form = await request.form()
        username = str(form.get("username", form.get("email", "")))
        password = str(form.get("password", ""))

        settings = get_settings()
        ok = (
            username.strip() == settings.admin_username
            and password == settings.admin_password
        )
        if ok:
            request.session["admin_user"] = username
        return ok

    async def logout(self, request: Request) -> bool:
        request.session.clear()
        return True

    async def authenticate(self, request: Request) -> bool:
        return bool(request.session.get("admin_user"))
