from collections import OrderedDict
from datetime import datetime

import pytz

from fastapi import Request

import aurweb.config


def tz_offset(tz):
    """ The literal timezone name: UTC, America/Los_Angeles, etc. """
    orig = datetime.now(pytz.timezone(tz)).strftime("%z")
    return orig[:3] + ":" + orig[3:]


SUPPORTED_TIMEZONES = OrderedDict({
    # Flatten out the list of tuples into an OrderedDict.
    timezone[0]: timezone[1] for timezone in sorted([
        # Comprehend a list of tuples (timezone, offset display string)
        # and sort them by (offset, timezone).
        (tz, "(UTC%s) %s" % (tz_offset(tz), tz))
        for tz in pytz.all_timezones
    ], key=lambda e: (tz_offset(e[0]), e[0]))
})


def get_request_timezone(request: Request):
    """ Get a request's timezone by its AURTZ cookie. We use the
    configuration's [options] default_timezone otherwise.

    @param request FastAPI request
    """
    if request.user.is_authenticated():
        return request.user.Timezone
    default_tz = aurweb.config.get("options", "default_timezone")
    return request.cookies.get("AURTZ", default_tz)
