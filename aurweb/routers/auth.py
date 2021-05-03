#!/usr/bin/python3
""" AURWeb's primary routing module. Define all routes via @app.app.{get,post}
decorators in some way; more complex routes should be defined in their
own modules and imported here. """
from datetime import datetime
from http import HTTPStatus

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

import aurweb.config

from aurweb.auth import auth_required
from aurweb.models.user import User
from aurweb.templates import make_context, render_template

router = APIRouter()


def login_template(request: Request, next: str, errors: list = None):
    """ Provide login-specific template context to render_template. """
    context = make_context(request, "Login", next)
    context["errors"] = errors
    context["url_base"] = f"{request.url.scheme}://{request.url.netloc}"
    return render_template(request, "login.html", context)


@router.get("/login", response_class=HTMLResponse)
@auth_required(False)
async def login_get(request: Request, next: str = "/"):
    return login_template(request, next)


@router.post("/login", response_class=HTMLResponse)
@auth_required(False)
async def login_post(request: Request,
                     next: str = Form(...),
                     user: str = Form(default=str()),
                     passwd: str = Form(default=str()),
                     remember_me: bool = Form(default=False)):
    from aurweb.db import session

    user = session.query(User).filter(User.Username == user).first()
    if not user:
        return login_template(request, next,
                              errors=["Bad username or password."])

    cookie_timeout = 0

    if remember_me:
        cookie_timeout = aurweb.config.getint(
            "options", "persistent_cookie_timeout")

    _, sid = user.login(request, passwd, cookie_timeout)
    if not _:
        return login_template(request, next,
                              errors=["Bad username or password."])

    expires_at = datetime.utcnow().timestamp() + cookie_timeout

    response = RedirectResponse(url=next,
                                status_code=int(HTTPStatus.SEE_OTHER))
    response.set_cookie("AURSID", sid, expires=expires_at)
    return response


@router.get("/logout")
@auth_required()
async def logout(request: Request, next: str = "/"):
    """ A GET and POST route for logging out.

    @param request FastAPI request
    @param next Route to redirect to
    """
    if request.user.is_authenticated():
        request.user.logout(request)

    # Use 303 since we may be handling a post request, that'll get it
    # to redirect to a get request.
    response = RedirectResponse(url=next,
                                status_code=int(HTTPStatus.SEE_OTHER))
    response.delete_cookie("AURSID")
    return response


@router.post("/logout")
@auth_required()
async def logout_post(request: Request, next: str = "/"):
    return await logout(request=request, next=next)
