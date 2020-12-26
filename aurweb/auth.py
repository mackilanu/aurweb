from datetime import datetime

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
