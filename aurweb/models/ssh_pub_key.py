from sqlalchemy.orm import backref, mapper, relationship

from aurweb.models.user import User
from aurweb.schema import SSHPubKeys


class SSHPubKey:
    def __init__(self, **kwargs):
        self.UserID = kwargs.get("UserID")
        self.Fingerprint = kwargs.get("Fingerprint")
        self.PubKey = kwargs.get("PubKey")


mapper(SSHPubKey, SSHPubKeys, properties={
    "User": relationship(User, backref=backref("ssh_pub_key", uselist=False))
})
