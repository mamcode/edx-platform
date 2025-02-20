"""
Views for login / logout and associated functionality

Much of this file was broken out from views.py, previous history can be found there.
"""

from __future__ import absolute_import

import logging

import six
from django.conf import settings
from django.contrib.auth import authenticate
from django.contrib.auth import login as django_login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.http import HttpResponse
from django.utils.translation import ugettext as _
from django.views.decorators.csrf import csrf_exempt, ensure_csrf_cookie
from django.views.decorators.http import require_http_methods
from ratelimitbackend.exceptions import RateLimitException

import third_party_auth
from edxmako.shortcuts import render_to_response
from openedx.core.djangoapps.password_policy import compliance as password_policy_compliance
from openedx.core.djangoapps.site_configuration import helpers as configuration_helpers
from openedx.core.djangoapps.user_authn.cookies import refresh_jwt_cookies, set_logged_in_cookies
from openedx.core.djangoapps.user_authn.exceptions import AuthFailedError
from openedx.core.djangoapps.util.user_messages import PageLevelMessages
from openedx.core.djangolib.markup import HTML, Text
from student.forms import send_password_reset_email_for_user
from student.models import LoginFailures
from student.views import send_reactivation_email_for_user
from third_party_auth import pipeline, provider
from track import segment
from util.json_request import JsonResponse
from util.password_policy_validators import normalize_password

log = logging.getLogger("edx.student")
AUDIT_LOG = logging.getLogger("audit")


def _do_third_party_auth(request):
    """
    User is already authenticated via 3rd party, now try to find and return their associated Django user.
    """
    running_pipeline = pipeline.get(request)
    username = running_pipeline['kwargs'].get('username')
    backend_name = running_pipeline['backend']
    third_party_uid = running_pipeline['kwargs']['uid']
    requested_provider = provider.Registry.get_from_pipeline(running_pipeline)
    platform_name = configuration_helpers.get_value("platform_name", settings.PLATFORM_NAME)

    try:
        return pipeline.get_authenticated_user(requested_provider, username, third_party_uid)
    except User.DoesNotExist:
        AUDIT_LOG.info(
            u"Login failed - user with username {username} has no social auth "
            u"with backend_name {backend_name}".format(
                username=username, backend_name=backend_name)
        )
        message = Text(_(
            u"You've successfully signed in to your {provider_name} account, "
            u"but this account isn't linked with your {platform_name} account yet. {blank_lines}"
            u"Use your {platform_name} username and password to sign in to {platform_name} below, "
            u"and then link your {platform_name} account with {provider_name} from your dashboard. {blank_lines}"
            u"If you don't have an account on {platform_name} yet, "
            u"click {register_label_strong} at the top of the page."
        )).format(
            blank_lines=HTML('<br/><br/>'),
            platform_name=platform_name,
            provider_name=requested_provider.name,
            register_label_strong=HTML('<strong>{register_text}</strong>').format(
                register_text=_('Register')
            )
        )

        raise AuthFailedError(message)


def _get_user_by_email(request):
    """
    Finds a user object in the database based on the given request, ignores all fields except for email.
    """
    if 'email' not in request.POST or 'password' not in request.POST:
        raise AuthFailedError(_('There was an error receiving your login information. Please email us.'))

    email = request.POST['email']

    try:
        return User.objects.get(email=email)
    except User.DoesNotExist:
        if settings.FEATURES['SQUELCH_PII_IN_LOGS']:
            AUDIT_LOG.warning(u"Login failed - Unknown user email")
        else:
            AUDIT_LOG.warning(u"Login failed - Unknown user email: {0}".format(email))


def _check_excessive_login_attempts(user):
    """
    See if account has been locked out due to excessive login failures
    """
    if user and LoginFailures.is_feature_enabled():
        if LoginFailures.is_user_locked_out(user):
            raise AuthFailedError(_('This account has been temporarily locked due '
                                    'to excessive login failures. Try again later.'))


def _enforce_password_policy_compliance(request, user):
    try:
        password_policy_compliance.enforce_compliance_on_login(user, request.POST.get('password'))
    except password_policy_compliance.NonCompliantPasswordWarning as e:
        # Allow login, but warn the user that they will be required to reset their password soon.
        PageLevelMessages.register_warning_message(request, six.text_type(e))
    except password_policy_compliance.NonCompliantPasswordException as e:
        send_password_reset_email_for_user(user, request)
        # Prevent the login attempt.
        raise AuthFailedError(HTML(six.text_type(e)))


def _generate_not_activated_message(user):
    """
    Generates the message displayed on the sign-in screen when a learner attempts to access the
    system with an inactive account.
    """

    support_url = configuration_helpers.get_value(
        'SUPPORT_SITE_LINK',
        settings.SUPPORT_SITE_LINK
    )

    platform_name = configuration_helpers.get_value(
        'PLATFORM_NAME',
        settings.PLATFORM_NAME
    )
    not_activated_message = Text(_(
        u'In order to sign in, you need to activate your account.{blank_lines}'
        u'We just sent an activation link to {email_strong}. If '
        u'you do not receive an email, check your spam folders or '
        u'{link_start}contact {platform_name} Support{link_end}.'
    )).format(
        platform_name=platform_name,
        blank_lines=HTML('<br/><br/>'),
        email_strong=HTML('<strong>{email}</strong>').format(email=user.email),
        link_start=HTML(u'<a href="{support_url}">').format(
            support_url=support_url,
        ),
        link_end=HTML("</a>"),
    )

    return not_activated_message


def _log_and_raise_inactive_user_auth_error(unauthenticated_user):
    """
    Depending on Django version we can get here a couple of ways, but this takes care of logging an auth attempt
    by an inactive user, re-sending the activation email, and raising an error with the correct message.
    """
    if settings.FEATURES['SQUELCH_PII_IN_LOGS']:
        AUDIT_LOG.warning(
            u"Login failed - Account not active for user.id: {0}, resending activation".format(
                unauthenticated_user.id)
        )
    else:
        AUDIT_LOG.warning(u"Login failed - Account not active for user {0}, resending activation".format(
            unauthenticated_user.username)
        )

    send_reactivation_email_for_user(unauthenticated_user)
    raise AuthFailedError(_generate_not_activated_message(unauthenticated_user))


def _authenticate_first_party(request, unauthenticated_user):
    """
    Use Django authentication on the given request, using rate limiting if configured
    """

    # If the user doesn't exist, we want to set the username to an invalid username so that authentication is guaranteed
    # to fail and we can take advantage of the ratelimited backend
    username = unauthenticated_user.username if unauthenticated_user else ""

    try:
        password = normalize_password(request.POST['password'])
        return authenticate(
            username=username,
            password=password,
            request=request
        )

    # This occurs when there are too many attempts from the same IP address
    except RateLimitException:
        raise AuthFailedError(_('Too many failed login attempts. Try again later.'))


def _handle_failed_authentication(user, authenticated_user):
    """
    Handles updating the failed login count, inactive user notifications, and logging failed authentications.
    """
    if user:
        if LoginFailures.is_feature_enabled():
            LoginFailures.increment_lockout_counter(user)

        if authenticated_user and not user.is_active:
            _log_and_raise_inactive_user_auth_error(user)

        # if we didn't find this username earlier, the account for this email
        # doesn't exist, and doesn't have a corresponding password
        if settings.FEATURES['SQUELCH_PII_IN_LOGS']:
            loggable_id = user.id if user else "<unknown>"
            AUDIT_LOG.warning(u"Login failed - password for user.id: {0} is invalid".format(loggable_id))
        else:
            AUDIT_LOG.warning(u"Login failed - password for {0} is invalid".format(user.email))

    raise AuthFailedError(_('Email or password is incorrect.'))


def _handle_successful_authentication_and_login(user, request):
    """
    Handles clearing the failed login counter, login tracking, and setting session timeout.
    """
    if LoginFailures.is_feature_enabled():
        LoginFailures.clear_lockout_counter(user)

    _track_user_login(user, request)

    try:
        django_login(request, user)
        request.session.set_expiry(604800 * 4)
        log.debug("Setting user session expiry to 4 weeks")
    except Exception as exc:
        AUDIT_LOG.critical("Login failed - Could not create session. Is memcached running?")
        log.critical("Login failed - Could not create session. Is memcached running?")
        log.exception(exc)
        raise


def _track_user_login(user, request):
    """
    Sends a tracking event for a successful login.
    """
    # .. pii: Username and email are sent to Segment here. Retired directly through Segment API call in Tubular.
    # .. pii_types: email_address, username
    # .. pii_retirement: third_party
    segment.identify(
        user.id,
        {
            'email': request.POST.get('email'),
            'username': user.username
        },
        {
            # Disable MailChimp because we don't want to update the user's email
            # and username in MailChimp on every page load. We only need to capture
            # this data on registration/activation.
            'MailChimp': False
        }
    )
    segment.track(
        user.id,
        "edx.bi.user.account.authenticated",
        {
            'category': "conversion",
            'label': request.POST.get('course_id'),
            'provider': None
        },
    )


@login_required
@require_http_methods(['GET'])
def finish_auth(request):  # pylint: disable=unused-argument
    """ Following logistration (1st or 3rd party), handle any special query string params.

    See FinishAuthView.js for details on the query string params.

    e.g. auto-enroll the user in a course, set email opt-in preference.

    This view just displays a "Please wait" message while AJAX calls are made to enroll the
    user in the course etc. This view is only used if a parameter like "course_id" is present
    during login/registration/third_party_auth. Otherwise, there is no need for it.

    Ideally this view will finish and redirect to the next step before the user even sees it.

    Args:
        request (HttpRequest)

    Returns:
        HttpResponse: 200 if the page was sent successfully
        HttpResponse: 302 if not logged in (redirect to login page)
        HttpResponse: 405 if using an unsupported HTTP method

    Example usage:

        GET /account/finish_auth/?course_id=course-v1:blah&enrollment_action=enroll

    """
    return render_to_response('student_account/finish_auth.html', {
        'disable_courseware_js': True,
        'disable_footer': True,
    })


@ensure_csrf_cookie
def login_user(request):
    """
    AJAX request to log in the user.
    """
    third_party_auth_requested = third_party_auth.is_enabled() and pipeline.running(request)
    first_party_auth_requested = bool(request.POST.get('email')) or bool(request.POST.get('password'))
    is_user_third_party_authenticated = False

    try:
        if third_party_auth_requested and not first_party_auth_requested:
            # The user has already authenticated via third-party auth and has not
            # asked to do first party auth by supplying a username or password. We
            # now want to put them through the same logging and cookie calculation
            # logic as with first-party auth.

            # This nested try is due to us only returning an HttpResponse in this
            # one case vs. JsonResponse everywhere else.
            try:
                user = _do_third_party_auth(request)
                is_user_third_party_authenticated = True
            except AuthFailedError as e:
                return HttpResponse(e.value, content_type="text/plain", status=403)
        else:
            user = _get_user_by_email(request)

        _check_excessive_login_attempts(user)

        possibly_authenticated_user = user

        if not is_user_third_party_authenticated:
            possibly_authenticated_user = _authenticate_first_party(request, user)
            if possibly_authenticated_user and password_policy_compliance.should_enforce_compliance_on_login():
                # Important: This call must be made AFTER the user was successfully authenticated.
                _enforce_password_policy_compliance(request, possibly_authenticated_user)

        if possibly_authenticated_user is None or not possibly_authenticated_user.is_active:
            _handle_failed_authentication(user, possibly_authenticated_user)

        _handle_successful_authentication_and_login(possibly_authenticated_user, request)

        redirect_url = None  # The AJAX method calling should know the default destination upon success
        if is_user_third_party_authenticated:
            running_pipeline = pipeline.get(request)
            redirect_url = pipeline.get_complete_url(backend_name=running_pipeline['backend'])

        response = JsonResponse({
            'success': True,
            'redirect_url': redirect_url,
        })

        # Ensure that the external marketing site can
        # detect that the user is logged in.
        return set_logged_in_cookies(request, response, possibly_authenticated_user)
    except AuthFailedError as error:
        log.exception(error.get_response())
        return JsonResponse(error.get_response())


# CSRF protection is not needed here because the only side effect
# of this endpoint is to refresh the cookie-based JWT, and attempting
# to get a CSRF token before we need to refresh adds too much
# complexity.
@csrf_exempt
@require_http_methods(['POST'])
def login_refresh(request):
    if not request.user.is_authenticated or request.user.is_anonymous:
        return JsonResponse('Unauthorized', status=401)

    try:
        response = JsonResponse({'success': True})
        return refresh_jwt_cookies(request, response, request.user)
    except AuthFailedError as error:
        log.exception(error.get_response())
        return JsonResponse(error.get_response(), status=400)
