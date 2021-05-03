import copy
import os

from datetime import datetime
from http import HTTPStatus

import jinja2
import pytz

from fastapi import Request
from fastapi.responses import HTMLResponse

import aurweb.config

from aurweb import l10n, time

# Prepare jinja2 objects.
loader = jinja2.FileSystemLoader(os.path.join(
    aurweb.config.get("options", "aurwebdir"), "templates"))
env = jinja2.Environment(loader=loader, autoescape=True,
                         extensions=["jinja2.ext.i18n"])


def is_list(value):
    """ Jinja2 filter indicating if value is a list or not. """
    return isinstance(value, list)


def is_str(value):
    """ Jinja2 filter indicating if value is a str or not. """
    return isinstance(value, str)


env.filters["tr"] = l10n.tr
env.filters["is_list"] = is_list
env.filters["is_str"] = is_str


def make_context(request: Request, title: str, next: str = None):
    """ Create a context for a jinja2 TemplateResponse. """

    timezone = time.get_request_timezone(request)
    return {
        "request": request,
        "language": l10n.get_request_language(request),
        "languages": l10n.SUPPORTED_LANGUAGES,
        "timezone": timezone,
        "timezones": time.SUPPORTED_TIMEZONES,
        "title": title,
        "now": datetime.now(tz=pytz.timezone(timezone)),
        "config": aurweb.config,
        "next": next if next else request.url.path
    }


def render_template(request: Request,
                    path: str,
                    context: dict,
                    status_code=int(HTTPStatus.OK)):
    """ Render a Jinja2 multi-lingual template with some context. """

    # Create a deep copy of our jinja2 environment. The environment in
    # total by itself is 48 bytes large (according to sys.getsizeof).
    # This is done so we can install gettext translations on the template
    # environment being rendered without installing them into a global
    # which is reused in this function.
    templates = copy.copy(env)

    translator = l10n.get_raw_translator_for_request(context.get("request"))
    templates.install_gettext_translations(translator)

    template = templates.get_template(path)
    rendered = template.render(context)

    response = HTMLResponse(rendered, status_code=status_code)
    response.set_cookie("AURLANG", context.get("language"))
    response.set_cookie("AURTZ", context.get("timezone"))
    return response
