from aurweb import config


def test_get():
    assert config.get("options", "disable_http_login") == "0"


def test_getboolean():
    assert config.getboolean("options", "disable_http_login") == False


def test_getint():
    assert config.getint("options", "disable_http_login") == 0
