import functools

from datetime import datetime
from http import HTTPStatus

from fastapi.responses import RedirectResponse
from starlette.authentication import AuthCredentials, AuthenticationBackend, AuthenticationError
from starlette.requests import HTTPConnection

from aurweb.models.session import Session
from aurweb.models.user import User


class AnonymousUser:
    @staticmethod
    def is_authenticated():
        return False


class BasicAuthBackend(AuthenticationBackend):
    async def authenticate(self, conn: HTTPConnection):
        from aurweb.db import session

        sid = conn.cookies.get("AURSID")
        if not sid:
            return None, AnonymousUser()

        now_ts = datetime.utcnow().timestamp()
        record = session.query(Session).filter(
            Session.SessionID == sid, Session.LastUpdateTS >= now_ts).first()
        if not record:
            return None, AnonymousUser()

        user = session.query(User).filter(User.ID == record.UsersID).first()
        if not user:
            raise AuthenticationError(f"Invalid User ID: {record.UsersID}")

        user.authenticated = True
        return AuthCredentials(["authenticated"]), user


def auth_required(is_required: bool = True, redirect: str = "/"):
    """ Authentication route decorator.

    @param is_required A boolean indicating whether the function requires auth
    @param redirect_to Path to redirect to if is_required isn't True
    """

    def decorator(func):
        @functools.wraps(func)
        async def wrapper(request, *args, **kwargs):
            if request.user.is_authenticated() != is_required:
                # If authentication is required, return UNAUTHORIZED,
                # otherwise return FORBIDDEN.
                status_code = int(HTTPStatus.UNAUTHORIZED
                                  if is_required else
                                  HTTPStatus.FORBIDDEN)
                return RedirectResponse(url=redirect, status_code=status_code)
            return await func(request, *args, **kwargs)
        return wrapper

    return decorator
