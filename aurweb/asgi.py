import http

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

import aurweb.config

from aurweb.db import get_engine
from aurweb.routers import html, sso

routes = set()

# Setup the FastAPI app.
app = FastAPI()
app.mount("/static/css",
          StaticFiles(directory="web/html/css"),
          name="static_css")
app.mount("/static/js",
          StaticFiles(directory="web/html/js"),
          name="static_js")
app.mount("/static/images",
          StaticFiles(directory="web/html/images"),
          name="static_images")


@app.on_event("startup")
async def app_startup():
    session_secret = aurweb.config.get("fastapi", "session_secret")
    if not session_secret:
        raise Exception("[fastapi] session_secret must not be empty")

    app.add_middleware(SessionMiddleware, secret_key=session_secret)
    app.include_router(sso.router)
    app.include_router(html.router)

    get_engine()

# NOTE: Always keep this dictionary updated with all routes
# that the application contains. We use this to check for
# parameter value verification.
routes = {route.path for route in app.routes}
routes.update({route.path for route in sso.router.routes})
routes.update({route.path for route in html.router.routes})


@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    """
    Dirty HTML error page to replace the default JSON error responses.
    In the future this should use a proper Arch-themed HTML template.
    """
    phrase = http.HTTPStatus(exc.status_code).phrase
    return HTMLResponse(f"<h1>{exc.status_code} {phrase}</h1><p>{exc.detail}</p>",
                        status_code=exc.status_code)
