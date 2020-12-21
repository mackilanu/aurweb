#!/usr/bin/python3
""" Test FastAPI application. """
from fastapi.testclient import TestClient

from aurweb.asgi import app

client = TestClient(app)


def test_index():
    """ Test the index route at '/'. """
    # Use `with` to trigger FastAPI app events.
    with client as req:
        response = req.get("/")
    assert response.status_code == 200


def test_favicon():
    """ Test the favicon route at '/favicon.ico'. """
    response1 = client.get("/static/images/favicon.ico")
    response2 = client.get("/favicon.ico")
    assert response1.status_code == 200
    assert response1.content == response2.content


def test_language():
    """ Test the language post route at '/language'. """
    post_data = {
        "set_lang": "de",
        "next": "/"
    }
    with client as req:
        response = client.post("/language", data=post_data)
    assert response.status_code == 302
