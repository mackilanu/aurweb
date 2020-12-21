#!/usr/bin/python3
""" AURWeb's primary routing module. Define all routes via @app.app.{get,post}
decorators in some way; more complex routes should be defined in their
own modules and imported here. """
from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from aurweb.templates import make_context, render_template

router = APIRouter()


@router.get("/favicon.ico")
async def favicon(request: Request):
    """ Some browsers attempt to find a website's favicon via root uri at
    /favicon.ico, so provide a redirection here to our static icon. """
    return RedirectResponse("/static/images/favicon.ico")


@router.post("/language", response_class=RedirectResponse)
async def language(request: Request,
                   set_lang: str = Form(...),
                   next: str = Form(...)):
    """ A POST route used to set a session's language. """
    # Return a 302 status, indicating that we're returning a GET response.
    response = RedirectResponse(url=next, status_code=302)
    response.set_cookie("AURLANG", set_lang)
    return response


@router.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """ Homepage route. """
    context = make_context(request, "Home")
    return render_template("index.html", context)
