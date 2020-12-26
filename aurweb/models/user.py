import hashlib
import random
import string

from datetime import datetime

import bcrypt

from fastapi import Request
from sqlalchemy import update
from sqlalchemy.orm import backref, mapper, relationship

from aurweb.models.account_type import AccountType
from aurweb.models.ban import is_banned
from aurweb.schema import Users


class User:
    """ An ORM model of a single Users record. """

    def __init__(self, **kwargs):
        self.AccountTypeID = kwargs.get("AccountTypeID")

        account_type = kwargs.get("AccountType")
        if account_type:
            self.AccountType = account_type

        self.Username = kwargs.get("Username")

        # No salt on user creation.
        self.Salt = None

        passwd = kwargs.get("Passwd")

        # If no Passwd was given, create an empty password. This will
        # never be matched against, all authentication functions hash
        # data and check against what is stored.
        # Otherwise, create a hash with a bcrypt generated salt with passwd.
        self.Passwd = str() if not passwd else \
            bcrypt.hashpw(kwargs.get("Passwd").encode(),
                          bcrypt.gensalt()).decode()

        self.Email = kwargs.get("Email")
        self.BackupEmail = kwargs.get("BackupEmail")
        self.RealName = kwargs.get("RealName")
        self.LangPreference = kwargs.get("LangPreference")
        self.Timezone = kwargs.get("Timezone")
        self.Homepage = kwargs.get("Homepage")
        self.IRCNick = kwargs.get("IRCNick")
        self.PGPKey = kwargs.get("PGPKey")
        self.RegistrationTS = kwargs.get("RegistrationTS")
        self.CommentNotify = kwargs.get("CommentNotify")
        self.UpdateNotify = kwargs.get("UpdateNotify")
        self.OwnershipNotify = kwargs.get("OwnershipNotify")
        self.SSOAccountID = kwargs.get("SSOAccountID")

        self._authenticated = False

    def is_authenticated(self):
        """ Return internal authenticated state. """
        return self._authenticated

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
            passwd = bcrypt.hashpw(password.encode("utf-8"),
                                   self.Salt.encode("utf-8")).decode("utf-8")
            self.Passwd = passwd

            stmt = update(User).where(User.ID == self.ID).values(Salt=self.Salt, Passwd=self.Passwd)
            session.execute(stmt)
            session.commit()

        return decision

    def _login_approved(self, request: Request):
        return \
            not is_banned(request) and \
            not self.Suspended

    def login(self, request: Request, password: str):
        """ Login and authenticate a request. """

        if not self._login_approved(request):
            return (False, None)

        self._authenticated = self.authenticate(password)
        if not self._authenticated:
            return (False, None)

        from aurweb.db import session
        from aurweb.models.session import Session

        self.LastLogin = datetime.utcnow()
        self.LastLoginIPAddress = request.client.host

        session.execute(update(User).where(User.ID == self.ID)
                        .values(LastLogin=self.LastLogin,
                                LastLoginIPAddress=self.LastLoginIPAddress))

        sid = ''.join(random.choices(string.ascii_uppercase +
                                     string.digits, k=32))

        user_session = session.query(Session)\
            .filter(Session.UsersID == self.ID).first()

        if not user_session:
            user_session = Session(UsersID=self.ID,
                                   SessionID=sid,
                                   LastUpdateTS=datetime.utcnow())
            session.add(user_session)
            session.commit()
        else:
            user_session.LastUpdateTS = datetime.utcnow()
            session.execute(update(Session)
                            .where(Session.UsersID == user_session.UsersID)
                            .values(LastUpdateTS=user_session.LastUpdateTS))
            session.commit()

        request.cookies["AURSID"] = sid

        return (self._authenticated, sid)

    def __repr__(self):
        return "<User(ID='%s', AccountType='%s', Username='%s')>" % (
            self.ID, str(self.AccountType), self.Username)


# Map schema.Users to User and give it some relationships.
mapper(User, Users, properties={
    "AccountType": relationship(AccountType,
                                backref=backref("users", lazy="dynamic"))
})
