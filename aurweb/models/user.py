import hashlib

from datetime import datetime

import bcrypt

from fastapi import Request
from sqlalchemy.orm import backref, make_transient, mapper, relationship

import aurweb.config

from aurweb.models.account_type import AccountType
from aurweb.models.ban import is_banned
from aurweb.schema import Users


class User:
    """ An ORM model of a single Users record. """
    authenticated = False

    def __init__(self, **kwargs):
        # Set AccountTypeID if it was passed.
        self.AccountTypeID = kwargs.get("AccountTypeID")

        account_type = kwargs.get("AccountType")
        if account_type:
            self.AccountType = account_type

        self.Username = kwargs.get("Username")

        # No salt on user creation.
        self.Salt = None

        # If no Passwd was given, create an empty password. This will
        # never be matched against, all authentication functions hash
        # data and check against what is stored.
        # Otherwise, create a hash with a bcrypt generated salt with passwd.
        passwd = kwargs.get("Passwd")
        self.Passwd = str() if not passwd else \
            bcrypt.hashpw(passwd.encode(), bcrypt.gensalt()).decode()

        self.ResetKey = kwargs.get("ResetKey")
        self.Email = kwargs.get("Email")
        self.BackupEmail = kwargs.get("BackupEmail")
        self.RealName = kwargs.get("RealName")
        self.LangPreference = kwargs.get("LangPreference")
        self.Timezone = kwargs.get("Timezone")
        self.Homepage = kwargs.get("Homepage")
        self.IRCNick = kwargs.get("IRCNick")
        self.PGPKey = kwargs.get("PGPKey")
        self.RegistrationTS = datetime.utcnow()
        self.CommentNotify = kwargs.get("CommentNotify")
        self.UpdateNotify = kwargs.get("UpdateNotify")
        self.OwnershipNotify = kwargs.get("OwnershipNotify")
        self.SSOAccountID = kwargs.get("SSOAccountID")

    def update_password(self, password):
        from aurweb.db import session
        self.Passwd = bcrypt.hashpw(password.encode(),
                                    bcrypt.gensalt()).decode()
        session.commit()

    @staticmethod
    def minimum_passwd_length():
        return aurweb.config.getint("options", "passwd_min_len")

    def is_authenticated(self):
        """ Return internal authenticated state. """
        return self.authenticated

    def authenticate(self, password: str):
        """ Check authentication against a given password. """
        from aurweb.db import session

        decision = False

        try:
            decision = bcrypt.checkpw(password.encode("utf-8"),
                                      self.Passwd.encode("utf-8"))
        except ValueError:
            pass

        if not decision and self.Salt != "":
            # If the first comparison failed, we can attempt to fallback
            # to md5 hash comparison with the internal salt value.
            # This mimics behavior in aurweb's legacy PHP codebase.
            decision = hashlib.md5(
                f"{self.Salt}{password}".encode("utf-8")
            ).hexdigest() == self.Passwd

            if not decision:
                return False

        # We got here, check to see if our md5 check passed.
        if decision:
            # If so, update internal salt and password with bcrypt.
            self.Salt = bcrypt.gensalt().decode("utf-8")
            self.Passwd = bcrypt.hashpw(
                password.encode("utf-8"),
                self.Salt.encode("utf-8")
            ).decode("utf-8")
            session.commit()

        return decision

    def _login_approved(self, request: Request):
        return not is_banned(request) and not self.Suspended

    def login(self, request: Request, password: str, session_time=0):
        """ Login and authenticate a request. """

        from aurweb.db import session
        from aurweb.models.session import Session, generate_unique_sid

        if not self._login_approved(request):
            return (False, None)

        self.authenticated = self.authenticate(password)
        if not self.authenticated:
            return (False, None)

        self.LastLogin = now_ts = datetime.utcnow().timestamp()
        self.LastLoginIPAddress = request.client.host
        session.commit()

        session_ts = now_ts + (
            session_time if session_time
            else aurweb.config.getint("options", "login_timeout")
        )

        sid = None

        if not self.session:
            sid = generate_unique_sid()
            self.session = Session(UsersID=self.ID, SessionID=sid,
                                   LastUpdateTS=session_ts)
            session.add(self.session)
        else:
            last_updated = self.session.LastUpdateTS
            if last_updated and last_updated < now_ts:
                # Existing session is expired. Delete it.
                current_session = self.session
                session.delete(self.session)
                session.commit()
                self.session = None

                # Alter the record to contain a new unique sid.
                make_transient(current_session)
                current_session.SessionID = sid = generate_unique_sid()

                # Add the record back with the new sid.
                session.add(current_session)
                session.commit()
                self.session = current_session

            else:
                # Session is still valid; retrieve the current SID.
                sid = self.session.SessionID

            self.session.LastUpdateTS = session_ts

        session.commit()

        request.cookies["AURSID"] = self.session.SessionID
        return (self.authenticated, sid)

    def logout(self, request):
        del request.cookies["AURSID"]
        self.authenticated = False

    def __repr__(self):
        return "<User(ID='%s', AccountType='%s', Username='%s')>" % (
            self.ID, str(self.AccountType), self.Username)


# Map schema.Users to User and give it some relationships.
mapper(User, Users, properties={
    "AccountType": relationship(AccountType,
                                backref=backref("users", lazy="dynamic"))
})
