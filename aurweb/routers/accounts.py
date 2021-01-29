import hashlib

from http import HTTPStatus

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import and_, or_

import aurweb.config

from aurweb import db, l10n, time, util
from aurweb.auth import auth_required
from aurweb.captcha import get_captcha_answer, get_captcha_salts, get_captcha_token
from aurweb.l10n import get_translator_for_request
from aurweb.models.account_type import AccountType
from aurweb.models.ban import Ban
from aurweb.models.ssh_pub_key import SSHPubKey
from aurweb.models.user import User
from aurweb.scripts.notify import ResetKeyNotification
from aurweb.templates import make_variable_context, render_template

router = APIRouter()


@router.get("/passreset", response_class=HTMLResponse)
@auth_required(False)
async def passreset(request: Request):
    context = await make_variable_context(request, "Password Reset")
    return render_template(request, "passreset.html", context)


@router.post("/passreset", response_class=HTMLResponse)
@auth_required(False)
async def passreset_post(request: Request,
                         user: str = Form(...),
                         resetkey: str = Form(default=None),
                         password: str = Form(default=None),
                         confirm: str = Form(default=None)):
    from aurweb.db import session

    context = await make_variable_context(request, "Password Reset")

    # The user parameter being required, we can match against
    user = db.query(User, or_(User.Username == user, User.Email == user)).first()
    if not user:
        context["errors"] = ["Invalid e-mail."]
        return render_template(request, "passreset.html", context,
                               status_code=int(HTTPStatus.NOT_FOUND))

    if resetkey:
        context["resetkey"] = resetkey

        if not user.ResetKey or resetkey != user.ResetKey:
            context["errors"] = ["Invalid e-mail."]
            return render_template(request, "passreset.html", context,
                                   status_code=int(HTTPStatus.NOT_FOUND))

        if not user or not password:
            context["errors"] = ["Missing a required field."]
            return render_template(request, "passreset.html", context,
                                   status_code=int(HTTPStatus.BAD_REQUEST))

        if password != confirm:
            # If the provided password does not match the provided confirm.
            context["errors"] = ["Password fields do not match."]
            return render_template(request, "passreset.html", context,
                                   status_code=int(HTTPStatus.BAD_REQUEST))

        if len(password) < User.minimum_passwd_length():
            # Translate the error here, which simplifies error output
            # in the jinja2 template.
            _ = get_translator_for_request(request)
            context["errors"] = [_(
                "Your password must be at least %s characters.") % (
                str(User.minimum_passwd_length()))]
            return render_template(request, "passreset.html", context,
                                   status_code=int(HTTPStatus.BAD_REQUEST))

        # We got to this point; everything matched up. Update the password
        # and remove the ResetKey.
        user.ResetKey = str()
        user.update_password(password)

        # Render ?step=complete.
        return RedirectResponse(url="/passreset?step=complete",
                                status_code=int(HTTPStatus.SEE_OTHER))

    # If we got here, we continue with issuing a resetkey for the user.
    resetkey = db.make_random_value(User, User.ResetKey)
    user.ResetKey = resetkey
    session.commit()

    executor = db.ConnectionExecutor(db.get_engine().raw_connection())
    ResetKeyNotification(executor, user.ID).send()

    # Render ?step=confirm.
    return RedirectResponse(url="/passreset?step=confirm",
                            status_code=int(HTTPStatus.SEE_OTHER))


def process_account_form(request, user, U: str = None, T: int = None,
                         E: str = None, H: str = None, BE: str = None,
                         R: str = None, HP: str = None, I: bool = None,
                         K: str = None, L: str = None, TZ: str = None,
                         P: str = None, C: str = None, PK: str = None,
                         CN: bool = None, UN: bool = None, ON: bool = None,
                         passwd: str = None,
                         captcha: str = None,
                         captcha_salt: str = None,
                         **kwargs):
    """ Process an account form. All fields are optional and only checks
    requirements in the case they are present.

    context = await make_variable_context(request, "Accounts")
    ok, errors = process_account_form(request, user, **kwargs)
    if not ok:
        context["errors"] = errors
        return render_template(request, "some_account_template.html", context)

    """

    # Get a local translator.
    _ = get_translator_for_request(request)

    host = request.client.host
    ban = db.query(Ban, Ban.IPAddress == host).first()
    if ban:
        return False, [
            "Account registration has been disabled for your " +
            "IP address, probably due to sustained spam attacks. " +
            "Sorry for the inconvenience."
        ]

    if request.user.is_authenticated():
        if not request.user.authenticate(passwd):
            return False, ["Invalid password."]

    if not E or not U:
        return False, ["Missing a required field."]

    username_min_len = aurweb.config.getint("options", "username_min_len")
    username_max_len = aurweb.config.getint("options", "username_max_len")
    if not util.valid_username(U):
        return False, [
            "The username is invalid.",
            [
                _("It must be between %s and %s characters long") % (
                    username_min_len, username_max_len),
                "Start and end with a letter or number",
                "Can contain only one period, underscore or hyphen.",
            ]
        ]

    if P:
        if not util.valid_password(P):
            return False, [
                _("Your password must be at least %s characters.") % (
                    username_min_len)
            ]
        elif not C:
            return False, ["Please confirm your new password."]
        elif P != C:
            return False, ["Password fields do not match."]

    if not util.valid_email(E):
        return False, ["The email address is invalid."]
    elif BE and not util.valid_email(BE):
        return False, ["The backup email address is invalid."]
    elif HP and not util.valid_homepage(HP):
        return False, [
            "The home page is invalid, please specify the full HTTP(s) URL."]
    elif K and not util.valid_pgp_fingerprint(K):
        return False, ["The PGP key fingerprint is invalid."]
    elif PK and not util.valid_ssh_pubkey(PK):
        return False, ["The SSH public key is invalid."]
    elif L and L not in l10n.SUPPORTED_LANGUAGES:
        return False, ["Language is not currently supported."]
    elif TZ and TZ not in time.SUPPORTED_TIMEZONES:
        return False, ["Timezone is not currently supported."]
    elif db.query(User, and_(User.ID != user.ID, User.Username == U)).first():
        # If the username already exists...
        return False, [
            _("The username, %s%s%s, is already in use.") % (
                "<strong>", U, "</strong>")
        ]
    elif db.query(User, and_(User.ID != user.ID, User.Email == E)).first():
        # If the email already exists...
        return False, [
            _("The address, %s%s%s, is already in use.") % (
                "<strong>", E, "</strong>")
        ]

    if PK:
        PK = PK.strip().rstrip()
        fingerprint = hashlib.sha256(PK.encode()).hexdigest()
        stanza = and_(SSHPubKey.UserID != user.ID,
                      SSHPubKey.Fingerprint == fingerprint)
        if db.query(SSHPubKey, stanza).first():
            return False, [
                _("The SSH public key, %s%s%s, is already in use.") % (
                    "<strong>", fingerprint, "</strong>")
            ]

    if captcha_salt and captcha_salt not in get_captcha_salts():
        return False, ["This CAPTCHA has expired. Please try again."]

    if captcha is not None:
        answer = get_captcha_answer(get_captcha_token(captcha_salt))
        if captcha != answer:
            return False, ["The entered CAPTCHA answer is invalid."]

    return True, []


@router.get("/register", response_class=HTMLResponse)
@auth_required(False)
async def account_register(request: Request,
                           U: str = Form(default=str()),    # Username
                           E: str = Form(default=str()),    # Email
                           H: str = Form(default=False),    # Hide Email
                           BE: str = Form(default=None),    # Backup Email
                           R: str = Form(default=None),     # Real Name
                           HP: str = Form(default=None),    # Homepage
                           I: str = Form(default=None),     # IRC Nick
                           K: str = Form(default=None),     # PGP Key FP
                           L: str = Form(default=aurweb.config.get(
                               "options", "default_lang")),
                           TZ: str = Form(default=aurweb.config.get(
                               "options", "default_timezone")),
                           PK: str = Form(default=None),
                           CN: bool = Form(default=False),  # Comment Notify
                           CU: bool = Form(default=False),  # Update Notify
                           CO: bool = Form(default=False),  # Owner Notify
                           captcha: str = Form(default=str())):
    context = await make_variable_context(request, "Register")
    context["captcha_salt"] = get_captcha_salts()[0]
    return render_template(request, "register.html", context)


@router.post("/register", response_class=HTMLResponse)
@auth_required(False)
async def account_register_post(request: Request,
                                U: str = Form(default=str()),  # Username
                                E: str = Form(default=str()),  # Email
                                H: str = Form(default=False),   # Hide Email
                                BE: str = Form(default=None),   # Backup Email
                                R: str = Form(default=''),    # Real Name
                                HP: str = Form(default=None),   # Homepage
                                I: str = Form(default=None),    # IRC Nick
                                K: str = Form(default=None),    # PGP Key
                                L: str = Form(default=aurweb.config.get(
                                    "options", "default_lang")),
                                TZ: str = Form(default=aurweb.config.get(
                                    "options", "default_timezone")),
                                PK: str = Form(default=None),   # SSH PubKey
                                CN: bool = Form(default=False),
                                UN: bool = Form(default=False),
                                ON: bool = Form(default=False),
                                captcha: str = Form(default=None),
                                captcha_salt: str = Form(...)):
    from aurweb.db import session

    context = await make_variable_context(request, "Register")
    ok, errors = process_account_form(request, request.user,
                                      **dict(await request.form()))

    if not ok:
        # If the field values given do not meet the requirements,
        # return HTTP 400 with an error.
        context["errors"] = errors
        return render_template(request, "register.html", context,
                               status_code=int(HTTPStatus.BAD_REQUEST))

    if not captcha:
        context["errors"] = ["The CAPTCHA is missing."]
        return render_template(request, "register.html", context,
                               status_code=int(HTTPStatus.BAD_REQUEST))

    # Create a user with no password with a resetkey, then send
    # an email off about it.
    resetkey = db.make_random_value(User, User.ResetKey)

    # By default, we grab the User account type to associate with.
    account_type = db.query(AccountType,
                            AccountType.AccountType == "User").first()

    # Create a user given all parameters available.
    user = db.create(User, Username=U, Email=E, HideEmail=H, BackupEmail=BE,
                     RealName=R, Homepage=HP, IRCNick=I, PGPKey=K,
                     LangPreference=L, Timezone=TZ, CommentNotify=CN,
                     UpdateNotify=UN, OwnershipNotify=ON, ResetKey=resetkey,
                     AccountType=account_type)

    # If a PK was given and either one does not exist or the given
    # PK mismatches the existing user's SSHPubKey.PubKey.
    if PK:
        # Get the second element in the PK, which is the actual key.
        pubkey = PK.strip().rstrip().split(" ")[1]
        fingerprint = hashlib.sha256(PK.encode()).hexdigest()
        user.ssh_pub_key = SSHPubKey(UserID=user.ID,
                                     PubKey=pubkey,
                                     Fingerprint=fingerprint)
        session.commit()

    # Send a reset key notification to the new user.
    executor = db.ConnectionExecutor(db.get_engine().raw_connection())
    ResetKeyNotification(executor, user.ID).send()

    return RedirectResponse(url="/register?step=complete",
                            status_code=int(HTTPStatus.SEE_OTHER))
