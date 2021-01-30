import os

from unittest import mock

import pytest

import aurweb.asgi
import aurweb.config


@pytest.mark.asyncio
async def test_asgi_startup_exception(monkeypatch):
    with mock.patch.dict(os.environ, {"AUR_CONFIG": "conf/config.defaults"}):
        aurweb.config.rehash()
        with pytest.raises(Exception):
            await aurweb.asgi.app_startup()
    aurweb.config.rehash()
