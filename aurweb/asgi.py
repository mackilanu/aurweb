import http
import os

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.middleware.sessions import SessionMiddleware

import aurweb.config

from aurweb.auth import BasicAuthBackend
from aurweb.db import get_engine
from aurweb.routers import accounts, auth, html, sso
from aurweb.templates import make_context, render_template


async def not_found(request, exc):
    context = make_context(request, "Not Found")
    return render_template(request, "not_found.html", context,
                           status_code=int(http.HTTPStatus.NOT_FOUND))

exception_handlers = {
    404: not_found
}

routes = set()

# Setup the FastAPI app.
app = FastAPI(exception_handlers=exception_handlers)

# Mount static directories.
app.mount("/static/css",
          StaticFiles(directory=os.path.join(
              aurweb.config.get("options", "aurwebdir"), "web/html/css")),
          name="static_css")
app.mount("/static/js",
          StaticFiles(directory=os.path.join(
              aurweb.config.get("options", "aurwebdir"), "web/html/js")),
          name="static_js")
app.mount("/static/images",
          StaticFiles(directory=os.path.join(
              aurweb.config.get("options", "aurwebdir"), "web/html/images")),
          name="static_images")


@app.on_event("startup")
async def app_startup():
    session_secret = aurweb.config.get("fastapi", "session_secret")
    if not session_secret:
        raise Exception("[fastapi] session_secret must not be empty")

    # Add application middlewares.
    app.add_middleware(AuthenticationMiddleware, backend=BasicAuthBackend())
    app.add_middleware(SessionMiddleware, secret_key=session_secret)

    # Add application routes.
    app.include_router(sso.router)
    app.include_router(html.router)
    app.include_router(auth.router)
    app.include_router(accounts.router)

    # Initialize the database engine and ORM.
    get_engine()

# NOTE: Always keep this dictionary updated with all routes
# that the application contains. We use this to check for
# parameter value verification.
routes = {route.path for route in app.routes}
routes.update({route.path for route in sso.router.routes})
routes.update({route.path for route in html.router.routes})
