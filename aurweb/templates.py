import copy
import os

from datetime import datetime

import jinja2

from fastapi import Request

from aurweb import config, l10n

# Prepare jinja2 objects.
loader = jinja2.FileSystemLoader(os.path.join(
    config.get("options", "aurwebdir"), "templates"))
env = jinja2.Environment(loader=loader, autoescape=True,
                         extensions=["jinja2.ext.i18n"])

# Add tr translation filter.
env.filters["tr"] = l10n.tr


def make_context(request: Request, title: str):
    """ Create a context for a jinja2 TemplateResponse.

    This method automates some fields for all users:
    TemplateResponse("index.html", make_context(request, "Home"))

    @param request HTTP request provided by FastAPI
    @param title The <title> portion used in "AUR (<lang>) - <title>"
    @returns A FastAPI context-compatible dictionary
    """

    return {
        "request": request,
        "lang": l10n.get_request_language(request),
        "languages": l10n.SUPPORTED_LANGUAGES,
        "title": title,
        "now": datetime.now(),
        "version": config.AURWEB_VERSION
    }


def render_template(path: str, context: dict):
    """ Render a Jinja2 multi-lingual template with some context.

    This process involves tying an i18n translator for the target
    language into the jinja2-ext-i18n extension.

    @param path Relative template path
    @param context A context dictionary created by make_context
    @returns A jinja2 rendered template
    """

    # Create a deep copy of our jinja2 environment. The environment in
    # total by itself is 48 bytes large (according to sys.getsizeof).
    # This is done so we can install gettext translations on the template
    # environment being rendered without installing them into a global
    # which is reused in this function.
    templates = copy.copy(env)

    translator = l10n.get_raw_translator_for_request(context.get("request"))
    templates.install_gettext_translations(translator)

    template = templates.get_template(path)
    return template.render(context, LANGUAGE=context.get("lang"))
