import pytest

from aurweb.models.account_type import get_account_type
from aurweb.models.ssh_pub_key import SSHPubKey
from aurweb.testing import setup_test_db
from aurweb.testing.models import make_user

user, ssh_pub_key = None, None


@pytest.fixture(autouse=True)
def setup():
    from aurweb.db import session

    global user, ssh_pub_key

    setup_test_db("Users", "SSHPubKeys")

    account_type = get_account_type("User")
    user = make_user(Username="test", Email="test@example.org",
                     RealName="Test User", Passwd="testPassword",
                     AccountType=account_type)

    assert account_type == user.AccountType
    assert account_type.ID == user.AccountTypeID

    ssh_pub_key = SSHPubKey(UserID=user.ID,
                            Fingerprint="testFingerprint",
                            PubKey="testPubKey")

    session.add(ssh_pub_key)
    session.commit()

    yield ssh_pub_key

    session.delete(ssh_pub_key)
    session.commit()


def test_ssh_pub_key():
    assert ssh_pub_key.UserID == user.ID
    assert ssh_pub_key.User == user
    assert ssh_pub_key.Fingerprint == "testFingerprint"
    assert ssh_pub_key.PubKey == "testPubKey"
