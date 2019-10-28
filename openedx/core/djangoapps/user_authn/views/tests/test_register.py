# -*- coding: utf-8 -*-
"""Tests for account creation"""
from __future__ import absolute_import

import json
import unicodedata
import unittest
from unittest import skipUnless
from datetime import datetime

import ddt
import httpretty
import mock
import pytz
import six
from django.conf import settings
from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import User
from django.core import mail
from django.test import TestCase, TransactionTestCase
from django.test.client import RequestFactory
from django.test.utils import override_settings
from django.urls import reverse

from social_django.models import Partial, UserSocialAuth

from lms.djangoapps.discussion.notification_prefs import NOTIFICATION_PREF_KEY
from openedx.core.djangoapps.django_comment_common.models import ForumsConfig
from openedx.core.djangoapps.lang_pref import LANGUAGE_KEY
from openedx.core.djangoapps.site_configuration.helpers import get_value
from openedx.core.djangoapps.site_configuration.tests.mixins import SiteMixin
from openedx.core.djangoapps.site_configuration.tests.test_util import with_site_configuration
from openedx.core.djangoapps.user_api.accounts import (
    EMAIL_MAX_LENGTH,
    EMAIL_MIN_LENGTH,
    NAME_MAX_LENGTH,
    USERNAME_MAX_LENGTH,
    USERNAME_MIN_LENGTH,
    USERNAME_BAD_LENGTH_MSG,
    USERNAME_INVALID_CHARS_ASCII,
    USERNAME_INVALID_CHARS_UNICODE
)
from openedx.core.djangoapps.user_api.accounts.api import get_account_settings
from openedx.core.djangoapps.user_api.accounts.tests.retirement_helpers import (
    RetirementTestCase,
    fake_requested_retirement,
)
from openedx.core.djangoapps.user_api.tests.test_helpers import TestCaseForm
from openedx.core.djangoapps.user_api.config.waffle import PREVENT_AUTH_USER_WRITES, waffle
from openedx.core.djangoapps.user_api.preferences.api import get_user_preference
from openedx.core.djangoapps.user_api.tests.test_constants import SORTED_COUNTRIES
from openedx.core.djangoapps.user_api.tests.test_views import UserAPITestCase
from openedx.core.djangoapps.user_authn.views.register import (
    REGISTRATION_AFFILIATE_ID,
    REGISTRATION_UTM_CREATED_AT,
    REGISTRATION_UTM_PARAMETERS,
    _skip_activation_email
)
from openedx.core.djangolib.testing.utils import CacheIsolationTestCase, skip_unless_lms
from student.models import UserAttribute
from student.tests.factories import UserFactory
from third_party_auth.tests import factories as third_party_auth_factory
from third_party_auth.tests.testutil import ThirdPartyAuthTestMixin, simulate_running_pipeline
from third_party_auth.tests.utils import (
    ThirdPartyOAuthTestMixin,
    ThirdPartyOAuthTestMixinFacebook,
    ThirdPartyOAuthTestMixinGoogle
)
from util.password_policy_validators import (
    create_validator_config,
    password_validators_instruction_texts,
    password_validators_restrictions
)

TEST_CS_URL = 'https://comments.service.test:123/'

TEST_USERNAME = 'test_user'
TEST_EMAIL = 'test@test.com'


def get_mock_pipeline_data(username=TEST_USERNAME, email=TEST_EMAIL):
    """
    Return mock pipeline data.
    """
    return {
        'backend': 'tpa-saml',
        'kwargs': {
            'username': username,
            'auth_entry': 'register',
            'request': {
                'SAMLResponse': [],
                'RelayState': [
                    'testshib-openedx'
                ]
            },
            'is_new': True,
            'new_association': True,
            'user': None,
            'social': None,
            'details': {
                'username': username,
                'fullname': 'Test Test',
                'last_name': 'Test',
                'first_name': 'Test',
                'email': email,
            },
            'response': {},
            'uid': 'testshib-openedx:{}'.format(username)
        }
    }


@ddt.ddt
@with_site_configuration(
    configuration={"extended_profile_fields": ["extra1", "extra2"]}
)
@override_settings(
    REGISTRATION_EXTRA_FIELDS={
        key: "optional"
        for key in [
            "level_of_education", "gender", "mailing_address", "city", "country", "goals",
            "year_of_birth"
        ]
    }
)
class TestCreateAccount(SiteMixin, TestCase):
    """Tests for account creation"""

    def setUp(self):
        super(TestCreateAccount, self).setUp()
        self.username = "test_user"
        self.url = reverse("create_account")
        self.request_factory = RequestFactory()
        self.params = {
            "username": self.username,
            "email": "test@example.org",
            "password": u"testpass",
            "name": "Test User",
            "honor_code": "true",
            "terms_of_service": "true",
        }

    @ddt.data("en", "eo")
    def test_default_lang_pref_saved(self, lang):
        with mock.patch("django.conf.settings.LANGUAGE_CODE", lang):
            response = self.client.post(self.url, self.params)
            self.assertEqual(response.status_code, 200)
            user = User.objects.get(username=self.username)
            self.assertEqual(get_user_preference(user, LANGUAGE_KEY), lang)

    @ddt.data("en", "eo")
    def test_header_lang_pref_saved(self, lang):
        response = self.client.post(self.url, self.params, HTTP_ACCEPT_LANGUAGE=lang)
        user = User.objects.get(username=self.username)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(get_user_preference(user, LANGUAGE_KEY), lang)

    def create_account_and_fetch_profile(self, host='test.localhost'):
        """
        Create an account with self.params, assert that the response indicates
        success, and return the UserProfile object for the newly created user
        """
        response = self.client.post(self.url, self.params, HTTP_HOST=host)
        self.assertEqual(response.status_code, 200)
        user = User.objects.get(username=self.username)
        return user.profile

    def test_create_account_and_normalize_password(self):
        """
        Test that unicode normalization on passwords is happening when a user registers.
        """
        # Set user password to NFKD format so that we can test that it is normalized to
        # NFKC format upon account creation.
        self.params['password'] = unicodedata.normalize('NFKD', u'Ṗŕệṿïệẅ Ṯệẍt')
        response = self.client.post(self.url, self.params)
        self.assertEqual(response.status_code, 200)

        user = User.objects.get(username=self.username)
        salt_val = user.password.split('$')[1]

        expected_user_password = make_password(unicodedata.normalize('NFKC', u'Ṗŕệṿïệẅ Ṯệẍt'), salt_val)
        self.assertEqual(expected_user_password, user.password)

    def test_marketing_cookie(self):
        response = self.client.post(self.url, self.params)
        self.assertEqual(response.status_code, 200)
        self.assertIn(settings.EDXMKTG_LOGGED_IN_COOKIE_NAME, self.client.cookies)
        self.assertIn(settings.EDXMKTG_USER_INFO_COOKIE_NAME, self.client.cookies)

    def test_profile_saved_no_optional_fields(self):
        profile = self.create_account_and_fetch_profile()
        self.assertEqual(profile.name, self.params["name"])
        self.assertEqual(profile.level_of_education, "")
        self.assertEqual(profile.gender, "")
        self.assertEqual(profile.mailing_address, "")
        self.assertEqual(profile.city, "")
        self.assertEqual(profile.country, "")
        self.assertEqual(profile.goals, "")
        self.assertEqual(
            profile.get_meta(),
            {
                "extra1": "",
                "extra2": "",
            }
        )
        self.assertIsNone(profile.year_of_birth)

    @override_settings(LMS_SEGMENT_KEY="testkey")
    @mock.patch('openedx.core.djangoapps.user_authn.views.register.segment.track')
    @mock.patch('openedx.core.djangoapps.user_authn.views.register.segment.identify')
    def test_segment_tracking(self, mock_segment_identify, _):
        year = datetime.now().year
        year_of_birth = year - 14
        self.params.update({
            "level_of_education": "a",
            "gender": "o",
            "mailing_address": "123 Example Rd",
            "city": "Exampleton",
            "country": "US",
            "goals": "To test this feature",
            "year_of_birth": str(year_of_birth),
            "extra1": "extra_value1",
            "extra2": "extra_value2",
        })

        expected_payload = {
            'email': self.params['email'],
            'username': self.params['username'],
            'name': self.params['name'],
            'age': 13,
            'yearOfBirth': year_of_birth,
            'education': 'Associate degree',
            'address': self.params['mailing_address'],
            'gender': 'Other/Prefer Not to Say',
            'country': self.params['country'],
        }

        profile = self.create_account_and_fetch_profile()

        mock_segment_identify.assert_called_with(profile.user.id, expected_payload)

    def test_profile_saved_all_optional_fields(self):
        self.params.update({
            "level_of_education": "a",
            "gender": "o",
            "mailing_address": "123 Example Rd",
            "city": "Exampleton",
            "country": "US",
            "goals": "To test this feature",
            "year_of_birth": "2015",
            "extra1": "extra_value1",
            "extra2": "extra_value2",
        })
        profile = self.create_account_and_fetch_profile()
        self.assertEqual(profile.level_of_education, "a")
        self.assertEqual(profile.gender, "o")
        self.assertEqual(profile.mailing_address, "123 Example Rd")
        self.assertEqual(profile.city, "Exampleton")
        self.assertEqual(profile.country, "US")
        self.assertEqual(profile.goals, "To test this feature")
        self.assertEqual(
            profile.get_meta(),
            {
                "extra1": "extra_value1",
                "extra2": "extra_value2",
            }
        )
        self.assertEqual(profile.year_of_birth, 2015)

    def test_profile_saved_empty_optional_fields(self):
        self.params.update({
            "level_of_education": "",
            "gender": "",
            "mailing_address": "",
            "city": "",
            "country": "",
            "goals": "",
            "year_of_birth": "",
            "extra1": "",
            "extra2": "",
        })
        profile = self.create_account_and_fetch_profile()
        self.assertEqual(profile.level_of_education, "")
        self.assertEqual(profile.gender, "")
        self.assertEqual(profile.mailing_address, "")
        self.assertEqual(profile.city, "")
        self.assertEqual(profile.country, "")
        self.assertEqual(profile.goals, "")
        self.assertEqual(
            profile.get_meta(),
            {"extra1": "", "extra2": ""}
        )
        self.assertEqual(profile.year_of_birth, None)

    def test_profile_year_of_birth_non_integer(self):
        self.params["year_of_birth"] = "not_an_integer"
        profile = self.create_account_and_fetch_profile()
        self.assertIsNone(profile.year_of_birth)

    @ddt.data(True, False)
    def test_discussions_email_digest_pref(self, digest_enabled):
        with mock.patch.dict("student.models.settings.FEATURES", {"ENABLE_DISCUSSION_EMAIL_DIGEST": digest_enabled}):
            response = self.client.post(self.url, self.params)
            self.assertEqual(response.status_code, 200)
            user = User.objects.get(username=self.username)
            preference = get_user_preference(user, NOTIFICATION_PREF_KEY)
            if digest_enabled:
                self.assertIsNotNone(preference)
            else:
                self.assertIsNone(preference)

    @unittest.skipUnless(settings.ROOT_URLCONF == 'lms.urls', 'Test only valid in lms')
    def test_affiliate_referral_attribution(self):
        """
        Verify that a referral attribution is recorded if an affiliate
        cookie is present upon a new user's registration.
        """
        affiliate_id = 'test-partner'
        self.client.cookies[settings.AFFILIATE_COOKIE_NAME] = affiliate_id
        user = self.create_account_and_fetch_profile().user
        self.assertEqual(UserAttribute.get_user_attribute(user, REGISTRATION_AFFILIATE_ID), affiliate_id)

    @unittest.skipUnless(settings.ROOT_URLCONF == 'lms.urls', 'Test only valid in lms')
    def test_utm_referral_attribution(self):
        """
        Verify that a referral attribution is recorded if an affiliate
        cookie is present upon a new user's registration.
        """
        utm_cookie_name = 'edx.test.utm'
        with mock.patch('student.models.RegistrationCookieConfiguration.current') as config:
            instance = config.return_value
            instance.utm_cookie_name = utm_cookie_name

            timestamp = 1475521816879
            utm_cookie = {
                'utm_source': 'test-source',
                'utm_medium': 'test-medium',
                'utm_campaign': 'test-campaign',
                'utm_term': 'test-term',
                'utm_content': 'test-content',
                'created_at': timestamp
            }

            created_at = datetime.fromtimestamp(timestamp / float(1000), tz=pytz.UTC)

            self.client.cookies[utm_cookie_name] = json.dumps(utm_cookie)
            user = self.create_account_and_fetch_profile().user
            self.assertEqual(
                UserAttribute.get_user_attribute(user, REGISTRATION_UTM_PARAMETERS.get('utm_source')),
                utm_cookie.get('utm_source')
            )
            self.assertEqual(
                UserAttribute.get_user_attribute(user, REGISTRATION_UTM_PARAMETERS.get('utm_medium')),
                utm_cookie.get('utm_medium')
            )
            self.assertEqual(
                UserAttribute.get_user_attribute(user, REGISTRATION_UTM_PARAMETERS.get('utm_campaign')),
                utm_cookie.get('utm_campaign')
            )
            self.assertEqual(
                UserAttribute.get_user_attribute(user, REGISTRATION_UTM_PARAMETERS.get('utm_term')),
                utm_cookie.get('utm_term')
            )
            self.assertEqual(
                UserAttribute.get_user_attribute(user, REGISTRATION_UTM_PARAMETERS.get('utm_content')),
                utm_cookie.get('utm_content')
            )
            self.assertEqual(
                UserAttribute.get_user_attribute(user, REGISTRATION_UTM_CREATED_AT),
                str(created_at)
            )

    @unittest.skipUnless(settings.ROOT_URLCONF == 'lms.urls', 'Test only valid in lms')
    def test_no_referral(self):
        """Verify that no referral is recorded when a cookie is not present."""
        utm_cookie_name = 'edx.test.utm'
        with mock.patch('student.models.RegistrationCookieConfiguration.current') as config:
            instance = config.return_value
            instance.utm_cookie_name = utm_cookie_name

            self.assertIsNone(self.client.cookies.get(settings.AFFILIATE_COOKIE_NAME))
            self.assertIsNone(self.client.cookies.get(utm_cookie_name))
            user = self.create_account_and_fetch_profile().user
            self.assertIsNone(UserAttribute.get_user_attribute(user, REGISTRATION_AFFILIATE_ID))
            self.assertIsNone(UserAttribute.get_user_attribute(user, REGISTRATION_UTM_PARAMETERS.get('utm_source')))
            self.assertIsNone(UserAttribute.get_user_attribute(user, REGISTRATION_UTM_PARAMETERS.get('utm_medium')))
            self.assertIsNone(UserAttribute.get_user_attribute(user, REGISTRATION_UTM_PARAMETERS.get('utm_campaign')))
            self.assertIsNone(UserAttribute.get_user_attribute(user, REGISTRATION_UTM_PARAMETERS.get('utm_term')))
            self.assertIsNone(UserAttribute.get_user_attribute(user, REGISTRATION_UTM_PARAMETERS.get('utm_content')))
            self.assertIsNone(UserAttribute.get_user_attribute(user, REGISTRATION_UTM_CREATED_AT))

    @unittest.skipUnless(settings.ROOT_URLCONF == 'lms.urls', 'Test only valid in lms')
    def test_incomplete_utm_referral(self):
        """Verify that no referral is recorded when a cookie is not present."""
        utm_cookie_name = 'edx.test.utm'
        with mock.patch('student.models.RegistrationCookieConfiguration.current') as config:
            instance = config.return_value
            instance.utm_cookie_name = utm_cookie_name

            utm_cookie = {
                'utm_source': 'test-source',
                'utm_medium': 'test-medium',
                # No campaign
                'utm_term': 'test-term',
                'utm_content': 'test-content',
                # No created at
            }

            self.client.cookies[utm_cookie_name] = json.dumps(utm_cookie)
            user = self.create_account_and_fetch_profile().user

            self.assertEqual(
                UserAttribute.get_user_attribute(user, REGISTRATION_UTM_PARAMETERS.get('utm_source')),
                utm_cookie.get('utm_source')
            )
            self.assertEqual(
                UserAttribute.get_user_attribute(user, REGISTRATION_UTM_PARAMETERS.get('utm_medium')),
                utm_cookie.get('utm_medium')
            )
            self.assertEqual(
                UserAttribute.get_user_attribute(user, REGISTRATION_UTM_PARAMETERS.get('utm_term')),
                utm_cookie.get('utm_term')
            )
            self.assertEqual(
                UserAttribute.get_user_attribute(user, REGISTRATION_UTM_PARAMETERS.get('utm_content')),
                utm_cookie.get('utm_content')
            )
            self.assertIsNone(
                UserAttribute.get_user_attribute(user, REGISTRATION_UTM_PARAMETERS.get('utm_campaign'))
            )
            self.assertIsNone(
                UserAttribute.get_user_attribute(user, REGISTRATION_UTM_CREATED_AT)
            )

    @mock.patch("openedx.core.djangoapps.site_configuration.helpers.get_value", mock.Mock(return_value=False))
    def test_create_account_not_allowed(self):
        """
        Test case to check user creation is forbidden when ALLOW_PUBLIC_ACCOUNT_CREATION feature flag is turned off
        """
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 403)

    def test_create_account_prevent_auth_user_writes(self):
        with waffle().override(PREVENT_AUTH_USER_WRITES, True):
            response = self.client.get(self.url)
            assert response.status_code == 403

    def test_created_on_site_user_attribute_set(self):
        profile = self.create_account_and_fetch_profile(host=self.site.domain)
        self.assertEqual(UserAttribute.get_user_attribute(profile.user, 'created_on_site'), self.site.domain)

    @ddt.data(
        (
            False, get_mock_pipeline_data(),
            {
                'SKIP_EMAIL_VALIDATION': False, 'AUTOMATIC_AUTH_FOR_TESTING': False,
            },
            False  # Do not skip activation email for normal scenario.
        ),
        (
            False, get_mock_pipeline_data(),
            {
                'SKIP_EMAIL_VALIDATION': True, 'AUTOMATIC_AUTH_FOR_TESTING': False,
            },
            True  # Skip activation email when `SKIP_EMAIL_VALIDATION` FEATURE flag is active.
        ),
        (
            False, get_mock_pipeline_data(),
            {
                'SKIP_EMAIL_VALIDATION': False, 'AUTOMATIC_AUTH_FOR_TESTING': True,
            },
            True  # Skip activation email when `AUTOMATIC_AUTH_FOR_TESTING` FEATURE flag is active.
        ),
        (
            True, get_mock_pipeline_data(),
            {
                'SKIP_EMAIL_VALIDATION': False, 'AUTOMATIC_AUTH_FOR_TESTING': False,
            },
            True  # Skip activation email if `skip_email_verification` is set for third party authentication.
        ),
        (
            False, get_mock_pipeline_data(email='invalid@yopmail.com'),
            {
                'SKIP_EMAIL_VALIDATION': False, 'AUTOMATIC_AUTH_FOR_TESTING': False,
            },
            False  # Send activation email when `skip_email_verification` is not set.
        )
    )
    @ddt.unpack
    @unittest.skipUnless(settings.ROOT_URLCONF == 'lms.urls', 'Test only valid in lms')
    def test_should_skip_activation_email(
            self, skip_email_verification, running_pipeline, feature_overrides, expected,
    ):
        """
        Test `skip_activation_email` works as expected.
        """
        third_party_provider = third_party_auth_factory.SAMLProviderConfigFactory(
            skip_email_verification=skip_email_verification,
        )
        user = UserFactory(username=TEST_USERNAME, email=TEST_EMAIL)

        with override_settings(FEATURES=dict(settings.FEATURES, **feature_overrides)):
            result = _skip_activation_email(
                user=user,
                running_pipeline=running_pipeline,
                third_party_provider=third_party_provider
            )

            assert result == expected


@ddt.ddt
class TestCreateAccountValidation(TestCase):
    """
    Test validation of various parameters in the create_account view
    """
    def setUp(self):
        super(TestCreateAccountValidation, self).setUp()
        self.url = reverse("user_api_registration")
        self.minimal_params = {
            "username": "test_username",
            "email": "test_email@example.com",
            "password": "test_password",
            "name": "Test Name",
            "honor_code": "true",
            "terms_of_service": "true",
        }

    def assert_success(self, params):
        """
        Request account creation with the given params and assert that the
        response properly indicates success
        """
        response = self.client.post(self.url, params)
        self.assertEqual(response.status_code, 200)
        response_data = json.loads(response.content.decode('utf-8'))
        self.assertTrue(response_data["success"])

    def assert_error(self, params, expected_field, expected_value):
        """
        Request account creation with the given params and assert that the
        response properly indicates an error with the given field and value
        """
        response = self.client.post(self.url, params)
        self.assertEqual(response.status_code, 400)
        response_data = json.loads(response.content.decode('utf-8'))
        self.assertFalse(response_data["success"])
        self.assertEqual(response_data["field"], expected_field)
        self.assertEqual(response_data["value"], expected_value)

    def test_minimal_success(self):
        self.assert_success(self.minimal_params)

    def test_username(self):
        params = dict(self.minimal_params)

        def assert_username_error(expected_error):
            """
            Assert that requesting account creation results in the expected
            error
            """
            self.assert_error(params, "username", expected_error)

        # Missing
        del params["username"]
        assert_username_error(USERNAME_BAD_LENGTH_MSG)

        # Empty, too short
        for username in ["", "a"]:
            params["username"] = username
            assert_username_error(USERNAME_BAD_LENGTH_MSG)

        # Too long
        params["username"] = "this_username_has_31_characters"
        assert_username_error(USERNAME_BAD_LENGTH_MSG)

        # Invalid
        params["username"] = "invalid username"
        assert_username_error(str(USERNAME_INVALID_CHARS_ASCII))

    def test_email(self):
        params = dict(self.minimal_params)

        def assert_email_error(expected_error):
            """
            Assert that requesting account creation results in the expected
            error
            """
            self.assert_error(params, "email", expected_error)

        # Missing
        del params["email"]
        assert_email_error("A properly formatted e-mail is required")

        # Empty
        params["email"] = ""
        assert_email_error("A properly formatted e-mail is required")

        #too short
        params["email"] = "a"
        assert_email_error("A properly formatted e-mail is required "
                           "Ensure this value has at least 3 characters (it has 1).")

        # Too long
        params["email"] = '{email}@example.com'.format(
            email='this_email_address_has_254_characters_in_it_so_it_is_unacceptable' * 4
        )

        # Assert that we get error when email has more than 254 characters.
        self.assertGreater(len(params['email']), 254)
        assert_email_error("Email cannot be more than 254 characters long")

        # Valid Email
        params["email"] = "student@edx.com"
        # Assert success on valid email
        self.assertLess(len(params["email"]), 254)
        self.assert_success(params)

        # Invalid
        params["email"] = "not_an_email_address"
        assert_email_error("A properly formatted e-mail is required")

    @override_settings(
        REGISTRATION_EMAIL_PATTERNS_ALLOWED=[
            r'.*@edx.org',  # Naive regex omitting '^', '$' and '\.' should still work.
            r'^.*@(.*\.)?example\.com$',
            r'^(^\w+\.\w+)@school.tld$',
        ]
    )
    @ddt.data(
        ('bob@we-are.bad', False),
        ('bob@edx.org.we-are.bad', False),
        ('staff@edx.org', True),
        ('student@example.com', True),
        ('student@sub.example.com', True),
        ('mr.teacher@school.tld', True),
        ('student1234@school.tld', False),
    )
    @ddt.unpack
    def test_email_pattern_requirements(self, email, expect_success):
        """
        Test the REGISTRATION_EMAIL_PATTERNS_ALLOWED setting, a feature which
        can be used to only allow people register if their email matches a
        against a whitelist of regexs.
        """
        params = dict(self.minimal_params)
        params["email"] = email
        if expect_success:
            self.assert_success(params)
        else:
            self.assert_error(params, "email", "Unauthorized email address.")

    def test_password(self):
        params = dict(self.minimal_params)

        def assert_password_error(expected_error):
            """
            Assert that requesting account creation results in the expected
            error
            """
            self.assert_error(params, "password", expected_error)

        # Missing
        del params["password"]
        assert_password_error("This field is required.")

        # Empty
        params["password"] = ""
        assert_password_error("This field is required.")

        # Too short
        params["password"] = "a"
        assert_password_error("This password is too short. It must contain at least 2 characters.")

        # Password policy is tested elsewhere

        # Matching username
        params["username"] = params["password"] = "test_username_and_password"
        assert_password_error("The password is too similar to the username.")

    def test_name(self):
        params = dict(self.minimal_params)

        def assert_name_error(expected_error):
            """
            Assert that requesting account creation results in the expected
            error
            """
            self.assert_error(params, "name", expected_error)

        # Missing
        del params["name"]
        assert_name_error("Your legal name must be a minimum of one character long")

        # Empty, too short
        params["name"] = ""
        assert_name_error("Your legal name must be a minimum of one character long")

    def test_honor_code(self):
        params = dict(self.minimal_params)

        def assert_honor_code_error(expected_error):
            """
            Assert that requesting account creation results in the expected
            error
            """
            self.assert_error(params, "honor_code", expected_error)

        with override_settings(REGISTRATION_EXTRA_FIELDS={"honor_code": "required"}):
            # Missing
            del params["honor_code"]
            assert_honor_code_error("To enroll, you must follow the honor code.")

            # Empty, invalid
            for honor_code in ["", "false", "not_boolean"]:
                params["honor_code"] = honor_code
                assert_honor_code_error("To enroll, you must follow the honor code.")

            # True
            params["honor_code"] = "tRUe"
            self.assert_success(params)

        with override_settings(REGISTRATION_EXTRA_FIELDS={"honor_code": "optional"}):
            # Missing
            del params["honor_code"]
            # Need to change username/email because user was created above
            params["username"] = "another_test_username"
            params["email"] = "another_test_email@example.com"
            self.assert_success(params)

    def test_terms_of_service(self):
        params = dict(self.minimal_params)

        def assert_terms_of_service_error(expected_error):
            """
            Assert that requesting account creation results in the expected
            error
            """
            self.assert_error(params, "terms_of_service", expected_error)

        # Missing
        del params["terms_of_service"]
        assert_terms_of_service_error("You must accept the terms of service.")

        # Empty, invalid
        for terms_of_service in ["", "false", "not_boolean"]:
            params["terms_of_service"] = terms_of_service
            assert_terms_of_service_error("You must accept the terms of service.")

        # True
        params["terms_of_service"] = "tRUe"
        self.assert_success(params)

    @ddt.data(
        ("level_of_education", 1, "A level of education is required"),
        ("gender", 1, "Your gender is required"),
        ("year_of_birth", 2, "Your year of birth is required"),
        ("mailing_address", 2, "Your mailing address is required"),
        ("goals", 2, "A description of your goals is required"),
        ("city", 2, "A city is required"),
        ("country", 2, "A country is required"),
        ("custom_field", 2, "You are missing one or more required fields")
    )
    @ddt.unpack
    def test_extra_fields(self, field, min_length, expected_error):
        params = dict(self.minimal_params)

        def assert_extra_field_error():
            """
            Assert that requesting account creation results in the expected
            error
            """
            self.assert_error(params, field, expected_error)

        with override_settings(REGISTRATION_EXTRA_FIELDS={field: "required"}):
            # Missing
            assert_extra_field_error()

            # Empty
            params[field] = ""
            assert_extra_field_error()

            # Too short
            if min_length > 1:
                params[field] = "a"
                assert_extra_field_error()


@mock.patch.dict("student.models.settings.FEATURES", {"ENABLE_DISCUSSION_SERVICE": True})
@mock.patch("openedx.core.djangoapps.django_comment_common.comment_client.User.base_url", TEST_CS_URL)
@mock.patch(
    "openedx.core.djangoapps.django_comment_common.comment_client.utils.requests.request",
    return_value=mock.Mock(status_code=200, text='{}')
)
class TestCreateCommentsServiceUser(TransactionTestCase):
    """ Tests for creating comments service user. """

    def setUp(self):
        super(TestCreateCommentsServiceUser, self).setUp()
        self.username = "test_user"
        self.url = reverse("create_account")
        self.params = {
            "username": self.username,
            "email": "test@example.org",
            "password": "testpass",
            "name": "Test User",
            "honor_code": "true",
            "terms_of_service": "true",
        }

        config = ForumsConfig.current()
        config.enabled = True
        config.save()

    def test_cs_user_created(self, request):
        "If user account creation succeeds, we should create a comments service user"
        response = self.client.post(self.url, self.params)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(request.called)
        args, kwargs = request.call_args
        self.assertEqual(args[0], 'put')
        self.assertTrue(args[1].startswith(TEST_CS_URL))
        self.assertEqual(kwargs['data']['username'], self.params['username'])

    @mock.patch("student.models.Registration.register", side_effect=Exception)
    def test_cs_user_not_created(self, register, request):
        "If user account creation fails, we should not create a comments service user"
        try:
            self.client.post(self.url, self.params)
        except:  # pylint: disable=bare-except
            pass
        with self.assertRaises(User.DoesNotExist):
            User.objects.get(username=self.username)
        self.assertTrue(register.called)
        self.assertFalse(request.called)


class TestUnicodeUsername(TestCase):
    """
    Test for Unicode usernames which is an optional feature.
    """

    def setUp(self):
        super(TestUnicodeUsername, self).setUp()
        self.url = reverse('create_account')

        # The word below reads "Omar II", in Arabic. It also contains a space and
        # an Eastern Arabic Number another option is to use the Esperanto fake
        # language but this was used instead to test non-western letters.
        self.username = u'عمر ٢'

        self.url_params = {
            'username': self.username,
            'email': 'unicode_user@example.com',
            "password": "testpass",
            'name': 'unicode_user',
            'terms_of_service': 'true',
            'honor_code': 'true',
        }

    @mock.patch.dict(settings.FEATURES, {'ENABLE_UNICODE_USERNAME': False})
    def test_with_feature_disabled(self):
        """
        Ensures backward-compatible defaults.
        """
        response = self.client.post(self.url, self.url_params)

        self.assertEquals(response.status_code, 400)
        obj = json.loads(response.content.decode('utf-8'))
        self.assertEquals(USERNAME_INVALID_CHARS_ASCII, obj['value'])

        with self.assertRaises(User.DoesNotExist):
            User.objects.get(email=self.url_params['email'])

    @mock.patch.dict(settings.FEATURES, {'ENABLE_UNICODE_USERNAME': True})
    def test_with_feature_enabled(self):
        response = self.client.post(self.url, self.url_params)
        self.assertEquals(response.status_code, 200)

        self.assertTrue(User.objects.get(email=self.url_params['email']))

    @mock.patch.dict(settings.FEATURES, {'ENABLE_UNICODE_USERNAME': True})
    def test_special_chars_with_feature_enabled(self):
        """
        Ensures that special chars are still prevented.
        """

        invalid_params = self.url_params.copy()
        invalid_params['username'] = '**john**'

        response = self.client.post(self.url, invalid_params)
        self.assertEquals(response.status_code, 400)

        obj = json.loads(response.content.decode('utf-8'))
        self.assertEquals(USERNAME_INVALID_CHARS_UNICODE, obj['value'])

        with self.assertRaises(User.DoesNotExist):
            User.objects.get(email=self.url_params['email'])


@ddt.ddt
@skip_unless_lms
class RegistrationViewValidationErrorTest(ThirdPartyAuthTestMixin, UserAPITestCase, RetirementTestCase):
    """
    Tests for catching duplicate email and username validation errors within
    the registration end-points of the User API.
    """

    maxDiff = None

    USERNAME = "bob"
    EMAIL = "bob@example.com"
    PASSWORD = "password"
    NAME = "Bob Smith"
    EDUCATION = "m"
    YEAR_OF_BIRTH = "1998"
    ADDRESS = "123 Fake Street"
    CITY = "Springfield"
    COUNTRY = "us"
    GOALS = "Learn all the things!"

    def setUp(self):
        super(RegistrationViewValidationErrorTest, self).setUp()
        self.url = reverse("user_api_registration")

    @mock.patch('openedx.core.djangoapps.user_api.views.check_account_exists')
    def test_register_retired_email_validation_error(self, dummy_check_account_exists):
        dummy_check_account_exists.return_value = []
        # Register the first user
        response = self.client.post(self.url, {
            "email": self.EMAIL,
            "name": self.NAME,
            "username": self.USERNAME,
            "password": self.PASSWORD,
            "honor_code": "true",
        })
        self.assertHttpOK(response)

        # Initiate retirement for the above user:
        fake_requested_retirement(User.objects.get(username=self.USERNAME))

        # Try to create a second user with the same email address as the retired user
        response = self.client.post(self.url, {
            "email": self.EMAIL,
            "name": "Someone Else",
            "username": "someone_else",
            "password": self.PASSWORD,
            "honor_code": "true",
        })
        self.assertEqual(response.status_code, 400)
        response_json = json.loads(response.content.decode('utf-8'))
        self.assertDictEqual(
            response_json,
            {
                "success": False,
                "email": [{
                    "user_message": (
                        u"It looks like {} belongs to an existing account. "
                        "Try again with a different email address."
                    ).format(
                        self.EMAIL
                    )
                }]
            }
        )

    def test_register_retired_email_validation_error_no_bypass_check_account_exists(self):
        """
        This test is the same as above, except it doesn't bypass check_account_exists.  Not bypassing this function
        results in the same error message, but a 409 status code rather than 400.
        """
        # Register the first user
        response = self.client.post(self.url, {
            "email": self.EMAIL,
            "name": self.NAME,
            "username": self.USERNAME,
            "password": self.PASSWORD,
            "honor_code": "true",
        })
        self.assertHttpOK(response)

        # Initiate retirement for the above user:
        fake_requested_retirement(User.objects.get(username=self.USERNAME))

        # Try to create a second user with the same email address as the retired user
        response = self.client.post(self.url, {
            "email": self.EMAIL,
            "name": "Someone Else",
            "username": "someone_else",
            "password": self.PASSWORD,
            "honor_code": "true",
        })
        self.assertEqual(response.status_code, 409)
        response_json = json.loads(response.content.decode('utf-8'))
        self.assertDictEqual(
            response_json,
            {
                "success": False,
                "email": [{
                    "user_message": (
                        u"It looks like {} belongs to an existing account. "
                        "Try again with a different email address."
                    ).format(
                        self.EMAIL
                    )
                }]
            }
        )

    def test_register_duplicate_retired_username_account_validation_error(self):
        # Register the first user
        response = self.client.post(self.url, {
            "email": self.EMAIL,
            "name": self.NAME,
            "username": self.USERNAME,
            "password": self.PASSWORD,
            "honor_code": "true",
        })
        self.assertHttpOK(response)

        # Initiate retirement for the above user.
        fake_requested_retirement(User.objects.get(username=self.USERNAME))

        with mock.patch('openedx.core.djangoapps.user_authn.views.register.do_create_account') as dummy_do_create_acct:
            # do_create_account should *not* be called - the duplicate retired username
            # should be detected by check_account_exists before account creation is called.
            dummy_do_create_acct.side_effect = Exception('do_create_account should *not* have been called!')
            # Try to create a second user with the same username.
            response = self.client.post(self.url, {
                "email": "someone+else@example.com",
                "name": "Someone Else",
                "username": self.USERNAME,
                "password": self.PASSWORD,
                "honor_code": "true",
            })
        self.assertEqual(response.status_code, 409)
        response_json = json.loads(response.content.decode('utf-8'))
        self.assertDictEqual(
            response_json,
            {
                "success": False,
                "username": [{
                    "user_message": (
                        u"It looks like {} belongs to an existing account. "
                        "Try again with a different username."
                    ).format(
                        self.USERNAME
                    )
                }]
            }
        )

    @mock.patch('openedx.core.djangoapps.user_api.views.check_account_exists')
    def test_register_duplicate_email_validation_error(self, dummy_check_account_exists):
        dummy_check_account_exists.return_value = []
        # Register the first user
        response = self.client.post(self.url, {
            "email": self.EMAIL,
            "name": self.NAME,
            "username": self.USERNAME,
            "password": self.PASSWORD,
            "honor_code": "true",
        })
        self.assertHttpOK(response)

        # Try to create a second user with the same email address
        response = self.client.post(self.url, {
            "email": self.EMAIL,
            "name": "Someone Else",
            "username": "someone_else",
            "password": self.PASSWORD,
            "honor_code": "true",
        })
        self.assertEqual(response.status_code, 400)
        response_json = json.loads(response.content.decode('utf-8'))
        self.assertDictEqual(
            response_json,
            {
                "success": False,
                "email": [{
                    "user_message": (
                        u"It looks like {} belongs to an existing account. "
                        "Try again with a different email address."
                    ).format(
                        self.EMAIL
                    )
                }]
            }
        )

    @mock.patch('openedx.core.djangoapps.user_api.views.check_account_exists')
    def test_register_duplicate_username_account_validation_error(self, dummy_check_account_exists):
        dummy_check_account_exists.return_value = []
        # Register the first user
        response = self.client.post(self.url, {
            "email": self.EMAIL,
            "name": self.NAME,
            "username": self.USERNAME,
            "password": self.PASSWORD,
            "honor_code": "true",
        })
        self.assertHttpOK(response)

        # Try to create a second user with the same username
        response = self.client.post(self.url, {
            "email": "someone+else@example.com",
            "name": "Someone Else",
            "username": self.USERNAME,
            "password": self.PASSWORD,
            "honor_code": "true",
        })
        self.assertEqual(response.status_code, 409)
        response_json = json.loads(response.content.decode('utf-8'))
        self.assertDictEqual(
            response_json,
            {
                u"success": False,
                u"username": [{
                    u"user_message": (
                        u"An account with the Public Username '{}' already exists."
                    ).format(
                        self.USERNAME
                    )
                }]
            }
        )

    @mock.patch('openedx.core.djangoapps.user_api.views.check_account_exists')
    def test_register_duplicate_username_and_email_validation_errors(self, dummy_check_account_exists):
        dummy_check_account_exists.return_value = []
        # Register the first user
        response = self.client.post(self.url, {
            "email": self.EMAIL,
            "name": self.NAME,
            "username": self.USERNAME,
            "password": self.PASSWORD,
            "honor_code": "true",
        })
        self.assertHttpOK(response)

        # Try to create a second user with the same username
        response = self.client.post(self.url, {
            "email": self.EMAIL,
            "name": "Someone Else",
            "username": self.USERNAME,
            "password": self.PASSWORD,
            "honor_code": "true",
        })
        self.assertEqual(response.status_code, 400)
        response_json = json.loads(response.content.decode('utf-8'))
        self.assertDictEqual(
            response_json,
            {
                "success": False,
                "email": [{
                    "user_message": (
                        u"It looks like {} belongs to an existing account. "
                        "Try again with a different email address."
                    ).format(
                        self.EMAIL
                    )
                }]
            }
        )


@ddt.ddt
@skip_unless_lms
class RegistrationViewTest(ThirdPartyAuthTestMixin, UserAPITestCase):
    """Tests for the registration end-points of the User API. """

    maxDiff = None

    USERNAME = "bob"
    EMAIL = "bob@example.com"
    PASSWORD = "password"
    NAME = "Bob Smith"
    EDUCATION = "m"
    YEAR_OF_BIRTH = "1998"
    ADDRESS = "123 Fake Street"
    CITY = "Springfield"
    COUNTRY = "us"
    GOALS = "Learn all the things!"
    PROFESSION_OPTIONS = [
        {
            "name": u'--',
            "value": u'',
            "default": True

        },
        {
            "value": u'software engineer',
            "name": u'Software Engineer',
            "default": False
        },
        {
            "value": u'teacher',
            "name": u'Teacher',
            "default": False
        },
        {
            "value": u'other',
            "name": u'Other',
            "default": False
        }
    ]
    SPECIALTY_OPTIONS = [
        {
            "name": u'--',
            "value": u'',
            "default": True

        },
        {
            "value": "aerospace",
            "name": "Aerospace",
            "default": False
        },
        {
            "value": u'early education',
            "name": u'Early Education',
            "default": False
        },
        {
            "value": u'n/a',
            "name": u'N/A',
            "default": False
        }
    ]
    link_template = u"<a href='/honor' rel='noopener' target='_blank'>{link_label}</a>"

    def setUp(self):
        super(RegistrationViewTest, self).setUp()
        self.url = reverse("user_api_registration")

    @ddt.data("get", "post")
    def test_auth_disabled(self, method):
        self.assertAuthDisabled(method, self.url)

    def test_allowed_methods(self):
        self.assertAllowedMethods(self.url, ["GET", "POST", "HEAD", "OPTIONS"])

    def test_put_not_allowed(self):
        response = self.client.put(self.url)
        self.assertHttpMethodNotAllowed(response)

    def test_delete_not_allowed(self):
        response = self.client.delete(self.url)
        self.assertHttpMethodNotAllowed(response)

    def test_patch_not_allowed(self):
        response = self.client.patch(self.url)
        self.assertHttpMethodNotAllowed(response)

    def test_register_form_default_fields(self):
        no_extra_fields_setting = {}

        self._assert_reg_field(
            no_extra_fields_setting,
            {
                u"name": u"email",
                u"type": u"email",
                u"required": True,
                u"label": u"Email",
                u"instructions": u"This is what you will use to login.",
                u"restrictions": {
                    "min_length": EMAIL_MIN_LENGTH,
                    "max_length": EMAIL_MAX_LENGTH
                },
            }
        )

        self._assert_reg_field(
            no_extra_fields_setting,
            {
                u"name": u"name",
                u"type": u"text",
                u"required": True,
                u"label": u"Full Name",
                u"instructions": u"This name will be used on any certificates that you earn.",
                u"restrictions": {
                    "max_length": 255
                },
            }
        )

        self._assert_reg_field(
            no_extra_fields_setting,
            {
                u"name": u"username",
                u"type": u"text",
                u"required": True,
                u"label": u"Public Username",
                u"instructions": u"The name that will identify you in your courses. "
                                 u"It cannot be changed later.",
                u"restrictions": {
                    "min_length": USERNAME_MIN_LENGTH,
                    "max_length": USERNAME_MAX_LENGTH
                },
            }
        )

        self._assert_reg_field(
            no_extra_fields_setting,
            {
                u"placeholder": "",
                u"name": u"password",
                u"type": u"password",
                u"required": True,
                u"label": u"Password",
                u"instructions": password_validators_instruction_texts(),
                u"restrictions": password_validators_restrictions(),
            }
        )

    @override_settings(AUTH_PASSWORD_VALIDATORS=[
        create_validator_config('util.password_policy_validators.MinimumLengthValidator', {'min_length': 2}),
        create_validator_config('util.password_policy_validators.UppercaseValidator', {'min_upper': 3}),
        create_validator_config('util.password_policy_validators.SymbolValidator', {'min_symbol': 1}),
    ])
    def test_register_form_password_complexity(self):
        no_extra_fields_setting = {}

        # Without enabling password policy
        self._assert_reg_field(
            no_extra_fields_setting,
            {
                u'name': u'password',
                u'label': u'Password',
                u"instructions": password_validators_instruction_texts(),
                u"restrictions": password_validators_restrictions(),
            }
        )

        msg = u'Your password must contain at least 2 characters, including '\
              u'3 uppercase letters & 1 symbol.'
        self._assert_reg_field(
            no_extra_fields_setting,
            {
                u'name': u'password',
                u'label': u'Password',
                u'instructions': msg,
                u"restrictions": password_validators_restrictions(),
            }
        )

    @override_settings(REGISTRATION_EXTENSION_FORM='openedx.core.djangoapps.user_api.tests.test_helpers.TestCaseForm')
    def test_extension_form_fields(self):
        no_extra_fields_setting = {}

        # Verify other fields didn't disappear for some reason.
        self._assert_reg_field(
            no_extra_fields_setting,
            {
                u"name": u"email",
                u"type": u"email",
                u"required": True,
                u"label": u"Email",
                u"instructions": u"This is what you will use to login.",
                u"restrictions": {
                    "min_length": EMAIL_MIN_LENGTH,
                    "max_length": EMAIL_MAX_LENGTH
                },
            }
        )

        self._assert_reg_field(
            no_extra_fields_setting,
            {
                u"name": u"favorite_editor",
                u"type": u"select",
                u"required": False,
                u"label": u"Favorite Editor",
                u"placeholder": u"cat",
                u"defaultValue": u"vim",
                u"errorMessages": {
                    u'required': u'This field is required.',
                    u'invalid_choice': u'Select a valid choice. %(value)s is not one of the available choices.',
                }
            }
        )

        self._assert_reg_field(
            no_extra_fields_setting,
            {
                u"name": u"favorite_movie",
                u"type": u"text",
                u"required": True,
                u"label": u"Fav Flick",
                u"placeholder": None,
                u"defaultValue": None,
                u"errorMessages": {
                    u'required': u'Please tell us your favorite movie.',
                    u'invalid': u"We're pretty sure you made that movie up."
                },
                u"restrictions": {
                    "min_length": TestCaseForm.MOVIE_MIN_LEN,
                    "max_length": TestCaseForm.MOVIE_MAX_LEN,
                }
            }
        )

    @ddt.data(
        ('pk', 'PK', 'Bob123', 'Bob123'),
        ('Pk', 'PK', None, ''),
        ('pK', 'PK', 'Bob123@edx.org', 'Bob123_edx_org'),
        ('PK', 'PK', 'Bob123123123123123123123123123123123123', 'Bob123123123123123123123123123'),
        ('us', 'US', 'Bob-1231231&23123+1231(2312312312@3123123123', 'Bob-1231231_23123_1231_2312312'),
    )
    @ddt.unpack
    def test_register_form_third_party_auth_running_google(
            self,
            input_country_code,
            expected_country_code,
            input_username,
            expected_username):
        no_extra_fields_setting = {}
        country_options = (
            [
                {
                    "name": "--",
                    "value": "",
                    "default": False
                }
            ] + [
                {
                    "value": country_code,
                    "name": six.text_type(country_name),
                    "default": True if country_code == expected_country_code else False
                }
                for country_code, country_name in SORTED_COUNTRIES
            ]
        )

        provider = self.configure_google_provider(enabled=True)
        with simulate_running_pipeline(
            "openedx.core.djangoapps.user_api.api.third_party_auth.pipeline", "google-oauth2",
            email="bob@example.com",
            fullname="Bob",
            username=input_username,
            country=input_country_code
        ):
            self._assert_password_field_hidden(no_extra_fields_setting)
            self._assert_social_auth_provider_present(no_extra_fields_setting, provider)

            # Email should be filled in
            self._assert_reg_field(
                no_extra_fields_setting,
                {
                    u"name": u"email",
                    u"defaultValue": u"bob@example.com",
                    u"type": u"email",
                    u"required": True,
                    u"label": u"Email",
                    u"instructions": u"This is what you will use to login.",
                    u"restrictions": {
                        "min_length": EMAIL_MIN_LENGTH,
                        "max_length": EMAIL_MAX_LENGTH
                    },
                }
            )

            # Full Name should be filled in
            self._assert_reg_field(
                no_extra_fields_setting,
                {
                    u"name": u"name",
                    u"defaultValue": u"Bob",
                    u"type": u"text",
                    u"required": True,
                    u"label": u"Full Name",
                    u"instructions": u"This name will be used on any certificates that you earn.",
                    u"restrictions": {
                        "max_length": NAME_MAX_LENGTH,
                    }
                }
            )

            # Username should be filled in
            self._assert_reg_field(
                no_extra_fields_setting,
                {
                    u"name": u"username",
                    u"defaultValue": expected_username,
                    u"type": u"text",
                    u"required": True,
                    u"label": u"Public Username",
                    u"instructions": u"The name that will identify you in your courses. "
                                     u"It cannot be changed later.",
                    u"restrictions": {
                        "min_length": USERNAME_MIN_LENGTH,
                        "max_length": USERNAME_MAX_LENGTH
                    }
                }
            )

            # Country should be filled in.
            self._assert_reg_field(
                {u"country": u"required"},
                {
                    u"label": u"Country or Region of Residence",
                    u"name": u"country",
                    u"defaultValue": expected_country_code,
                    u"type": u"select",
                    u"required": True,
                    u"options": country_options,
                    u"instructions": u"The country or region where you live.",
                    u"errorMessages": {
                        u"required": u"Select your country or region of residence."
                    },
                }
            )

    def test_register_form_level_of_education(self):
        self._assert_reg_field(
            {"level_of_education": "optional"},
            {
                "name": "level_of_education",
                "type": "select",
                "required": False,
                "label": "Highest level of education completed",
                "options": [
                    {"value": "", "name": "--", "default": True},
                    {"value": "p", "name": "Doctorate", "default": False},
                    {"value": "m", "name": "Master's or professional degree", "default": False},
                    {"value": "b", "name": "Bachelor's degree", "default": False},
                    {"value": "a", "name": "Associate degree", "default": False},
                    {"value": "hs", "name": "Secondary/high school", "default": False},
                    {"value": "jhs", "name": "Junior secondary/junior high/middle school", "default": False},
                    {"value": "el", "name": "Elementary/primary school", "default": False},
                    {"value": "none", "name": "No formal education", "default": False},
                    {"value": "other", "name": "Other education", "default": False},
                ],
                "errorMessages": {
                    "required": "Select the highest level of education you have completed."
                }
            }
        )

    @mock.patch('openedx.core.djangoapps.user_api.api._')
    def test_register_form_level_of_education_translations(self, fake_gettext):
        fake_gettext.side_effect = lambda text: text + ' TRANSLATED'

        self._assert_reg_field(
            {"level_of_education": "optional"},
            {
                "name": "level_of_education",
                "type": "select",
                "required": False,
                "label": "Highest level of education completed TRANSLATED",
                "options": [
                    {"value": "", "name": "--", "default": True},
                    {"value": "p", "name": "Doctorate TRANSLATED", "default": False},
                    {"value": "m", "name": "Master's or professional degree TRANSLATED", "default": False},
                    {"value": "b", "name": "Bachelor's degree TRANSLATED", "default": False},
                    {"value": "a", "name": "Associate degree TRANSLATED", "default": False},
                    {"value": "hs", "name": "Secondary/high school TRANSLATED", "default": False},
                    {"value": "jhs", "name": "Junior secondary/junior high/middle school TRANSLATED", "default": False},
                    {"value": "el", "name": "Elementary/primary school TRANSLATED", "default": False},
                    {"value": "none", "name": "No formal education TRANSLATED", "default": False},
                    {"value": "other", "name": "Other education TRANSLATED", "default": False},
                ],
                "errorMessages": {
                    "required": "Select the highest level of education you have completed."
                }
            }
        )

    def test_register_form_gender(self):
        self._assert_reg_field(
            {"gender": "optional"},
            {
                "name": "gender",
                "type": "select",
                "required": False,
                "label": "Gender",
                "options": [
                    {"value": "", "name": "--", "default": True},
                    {"value": "m", "name": "Male", "default": False},
                    {"value": "f", "name": "Female", "default": False},
                    {"value": "o", "name": "Other/Prefer Not to Say", "default": False},
                ],
            }
        )

    @mock.patch('openedx.core.djangoapps.user_api.api._')
    def test_register_form_gender_translations(self, fake_gettext):
        fake_gettext.side_effect = lambda text: text + ' TRANSLATED'

        self._assert_reg_field(
            {"gender": "optional"},
            {
                "name": "gender",
                "type": "select",
                "required": False,
                "label": "Gender TRANSLATED",
                "options": [
                    {"value": "", "name": "--", "default": True},
                    {"value": "m", "name": "Male TRANSLATED", "default": False},
                    {"value": "f", "name": "Female TRANSLATED", "default": False},
                    {"value": "o", "name": "Other/Prefer Not to Say TRANSLATED", "default": False},
                ],
            }
        )

    def test_register_form_year_of_birth(self):
        this_year = datetime.now(pytz.UTC).year
        year_options = (
            [
                {
                    "value": "",
                    "name": "--",
                    "default": True
                }
            ] + [
                {
                    "value": six.text_type(year),
                    "name": six.text_type(year),
                    "default": False
                }
                for year in range(this_year, this_year - 120, -1)
            ]
        )
        self._assert_reg_field(
            {"year_of_birth": "optional"},
            {
                "name": "year_of_birth",
                "type": "select",
                "required": False,
                "label": "Year of birth",
                "options": year_options,
            }
        )

    def test_register_form_profession_without_profession_options(self):
        self._assert_reg_field(
            {"profession": "required"},
            {
                "name": "profession",
                "type": "text",
                "required": True,
                "label": "Profession",
                "errorMessages": {
                    "required": "Enter your profession."
                }
            }
        )

    @with_site_configuration(
        configuration={
            "EXTRA_FIELD_OPTIONS": {"profession": ["Software Engineer", "Teacher", "Other"]}
        }
    )
    def test_register_form_profession_with_profession_options(self):
        self._assert_reg_field(
            {"profession": "required"},
            {
                "name": "profession",
                "type": "select",
                "required": True,
                "label": "Profession",
                "options": self.PROFESSION_OPTIONS,
                "errorMessages": {
                    "required": "Select your profession."
                },
            }
        )

    def test_register_form_specialty_without_specialty_options(self):
        self._assert_reg_field(
            {"specialty": "required"},
            {
                "name": "specialty",
                "type": "text",
                "required": True,
                "label": "Specialty",
                "errorMessages": {
                    "required": "Enter your specialty."
                }
            }
        )

    @with_site_configuration(
        configuration={
            "EXTRA_FIELD_OPTIONS": {"specialty": ["Aerospace", "Early Education", "N/A"]}
        }
    )
    def test_register_form_specialty_with_specialty_options(self):
        self._assert_reg_field(
            {"specialty": "required"},
            {
                "name": "specialty",
                "type": "select",
                "required": True,
                "label": "Specialty",
                "options": self.SPECIALTY_OPTIONS,
                "errorMessages": {
                    "required": "Select your specialty."
                },
            }
        )

    def test_registration_form_mailing_address(self):
        self._assert_reg_field(
            {"mailing_address": "optional"},
            {
                "name": "mailing_address",
                "type": "textarea",
                "required": False,
                "label": "Mailing address",
                "errorMessages": {
                    "required": "Enter your mailing address."
                }
            }
        )

    def test_registration_form_goals(self):
        self._assert_reg_field(
            {"goals": "optional"},
            {
                "name": "goals",
                "type": "textarea",
                "required": False,
                "label": u"Tell us why you're interested in {platform_name}".format(
                    platform_name=settings.PLATFORM_NAME
                ),
                "errorMessages": {
                    "required": "Tell us your goals."
                }
            }
        )

    def test_registration_form_city(self):
        self._assert_reg_field(
            {"city": "optional"},
            {
                "name": "city",
                "type": "text",
                "required": False,
                "label": "City",
                "errorMessages": {
                    "required": "Enter your city."
                }
            }
        )

    def test_registration_form_state(self):
        self._assert_reg_field(
            {"state": "optional"},
            {
                "name": "state",
                "type": "text",
                "required": False,
                "label": "State/Province/Region",
            }
        )

    def test_registration_form_country(self):
        country_options = (
            [
                {
                    "name": "--",
                    "value": "",
                    "default": True
                }
            ] + [
                {
                    "value": country_code,
                    "name": six.text_type(country_name),
                    "default": False
                }
                for country_code, country_name in SORTED_COUNTRIES
            ]
        )
        self._assert_reg_field(
            {"country": "required"},
            {
                "label": "Country or Region of Residence",
                "name": "country",
                "type": "select",
                "instructions": "The country or region where you live.",
                "required": True,
                "options": country_options,
                "errorMessages": {
                    "required": "Select your country or region of residence."
                },
            }
        )

    def test_registration_form_confirm_email(self):
        self._assert_reg_field(
            {"confirm_email": "required"},
            {
                "name": "confirm_email",
                "type": "text",
                "required": True,
                "label": "Confirm Email",
                "errorMessages": {
                    "required": "The email addresses do not match.",
                }
            }
        )

    @override_settings(
        MKTG_URLS={"ROOT": "https://www.test.com/", "HONOR": "honor"},
    )
    @mock.patch.dict(settings.FEATURES, {"ENABLE_MKTG_SITE": True})
    def test_registration_honor_code_mktg_site_enabled(self):
        link_template = "<a href='https://www.test.com/honor' rel='noopener' target='_blank'>{link_label}</a>"
        link_template2 = u"<a href='#' rel='noopener' target='_blank'>{link_label}</a>"
        link_label = "Terms of Service and Honor Code"
        link_label2 = "Privacy Policy"
        self._assert_reg_field(
            {"honor_code": "required"},
            {
                "label": (u"By creating an account, you agree to the {spacing}"
                          u"{link_label} {spacing}"
                          u"and you acknowledge that {platform_name} and each Member process your "
                          u"personal data in accordance {spacing}"
                          u"with the {link_label2}.").format(
                    platform_name=settings.PLATFORM_NAME,
                    link_label=link_template.format(link_label=link_label),
                    link_label2=link_template2.format(link_label=link_label2),
                    spacing=' ' * 18
                ),
                "name": "honor_code",
                "defaultValue": False,
                "type": "plaintext",
                "required": True,
                "errorMessages": {
                    "required": u"You must agree to the {platform_name} {link_label}".format(
                        platform_name=settings.PLATFORM_NAME,
                        link_label=link_label
                    )
                }
            }
        )

    @override_settings(MKTG_URLS_LINK_MAP={"HONOR": "honor"})
    @mock.patch.dict(settings.FEATURES, {"ENABLE_MKTG_SITE": False})
    def test_registration_honor_code_mktg_site_disabled(self):
        link_template = "<a href='/privacy' rel='noopener' target='_blank'>{link_label}</a>"
        link_label = "Terms of Service and Honor Code"
        link_label2 = "Privacy Policy"
        self._assert_reg_field(
            {"honor_code": "required"},
            {
                "label": (u"By creating an account, you agree to the {spacing}"
                          u"{link_label} {spacing}"
                          u"and you acknowledge that {platform_name} and each Member process your "
                          u"personal data in accordance {spacing}"
                          u"with the {link_label2}.").format(
                    platform_name=settings.PLATFORM_NAME,
                    link_label=self.link_template.format(link_label=link_label),
                    link_label2=link_template.format(link_label=link_label2),
                    spacing=' ' * 18
                ),
                "name": "honor_code",
                "defaultValue": False,
                "type": "plaintext",
                "required": True,
                "errorMessages": {
                    "required": u"You must agree to the {platform_name} {link_label}".format(
                        platform_name=settings.PLATFORM_NAME,
                        link_label=link_label
                    )
                }
            }
        )

    @override_settings(MKTG_URLS={
        "ROOT": "https://www.test.com/",
        "HONOR": "honor",
        "TOS": "tos",
    })
    @mock.patch.dict(settings.FEATURES, {"ENABLE_MKTG_SITE": True})
    def test_registration_separate_terms_of_service_mktg_site_enabled(self):
        # Honor code field should say ONLY honor code,
        # not "terms of service and honor code"
        link_label = 'Honor Code'
        link_template = u"<a href='https://www.test.com/honor' rel='noopener' target='_blank'>{link_label}</a>"
        self._assert_reg_field(
            {"honor_code": "required", "terms_of_service": "required"},
            {
                "label": u"I agree to the {platform_name} {link_label}".format(
                    platform_name=settings.PLATFORM_NAME,
                    link_label=link_template.format(link_label=link_label)
                ),
                "name": "honor_code",
                "defaultValue": False,
                "type": "checkbox",
                "required": True,
                "errorMessages": {
                    "required": u"You must agree to the {platform_name} {link_label}".format(
                        platform_name=settings.PLATFORM_NAME,
                        link_label=link_label
                    )
                }
            }
        )

        # Terms of service field should also be present
        link_label = "Terms of Service"
        link_template = u"<a href='https://www.test.com/tos' rel='noopener' target='_blank'>{link_label}</a>"
        self._assert_reg_field(
            {"honor_code": "required", "terms_of_service": "required"},
            {
                "label": u"I agree to the {platform_name} {link_label}".format(
                    platform_name=settings.PLATFORM_NAME,
                    link_label=link_template.format(link_label=link_label)
                ),
                "name": "terms_of_service",
                "defaultValue": False,
                "type": "checkbox",
                "required": True,
                "errorMessages": {
                    "required": u"You must agree to the {platform_name} {link_label}".format(
                        platform_name=settings.PLATFORM_NAME,
                        link_label=link_label
                    )
                }
            }
        )

    @override_settings(MKTG_URLS_LINK_MAP={"HONOR": "honor", "TOS": "tos"})
    @mock.patch.dict(settings.FEATURES, {"ENABLE_MKTG_SITE": False})
    def test_registration_separate_terms_of_service_mktg_site_disabled(self):
        # Honor code field should say ONLY honor code,
        # not "terms of service and honor code"
        link_label = 'Honor Code'
        self._assert_reg_field(
            {"honor_code": "required", "terms_of_service": "required"},
            {
                "label": u"I agree to the {platform_name} {link_label}".format(
                    platform_name=settings.PLATFORM_NAME,
                    link_label=self.link_template.format(link_label=link_label)
                ),
                "name": "honor_code",
                "defaultValue": False,
                "type": "checkbox",
                "required": True,
                "errorMessages": {
                    "required": u"You must agree to the {platform_name} Honor Code".format(
                        platform_name=settings.PLATFORM_NAME
                    )
                }
            }
        )

        link_label = 'Terms of Service'
        # Terms of service field should also be present
        link_template = u"<a href='/tos' rel='noopener' target='_blank'>{link_label}</a>"
        self._assert_reg_field(
            {"honor_code": "required", "terms_of_service": "required"},
            {
                "label": u"I agree to the {platform_name} {link_label}".format(
                    platform_name=settings.PLATFORM_NAME,
                    link_label=link_template.format(link_label=link_label)
                ),
                "name": "terms_of_service",
                "defaultValue": False,
                "type": "checkbox",
                "required": True,
                "errorMessages": {
                    "required": u"You must agree to the {platform_name} Terms of Service".format(
                        platform_name=settings.PLATFORM_NAME
                    )
                }
            }
        )

    @override_settings(
        REGISTRATION_EXTRA_FIELDS={
            "level_of_education": "optional",
            "gender": "optional",
            "year_of_birth": "optional",
            "mailing_address": "optional",
            "goals": "optional",
            "city": "optional",
            "state": "optional",
            "country": "required",
            "honor_code": "required",
            "confirm_email": "required",
        },
        REGISTRATION_EXTENSION_FORM='openedx.core.djangoapps.user_api.tests.test_helpers.TestCaseForm',
    )
    def test_field_order(self):
        response = self.client.get(self.url)
        self.assertHttpOK(response)

        # Verify that all fields render in the correct order
        form_desc = json.loads(response.content.decode('utf-8'))
        field_names = [field["name"] for field in form_desc["fields"]]
        self.assertEqual(field_names, [
            "email",
            "name",
            "username",
            "password",
            "favorite_movie",
            "favorite_editor",
            "confirm_email",
            "city",
            "state",
            "country",
            "gender",
            "year_of_birth",
            "level_of_education",
            "mailing_address",
            "goals",
            "honor_code",
        ])

    @override_settings(
        REGISTRATION_EXTRA_FIELDS={
            "level_of_education": "optional",
            "gender": "optional",
            "year_of_birth": "optional",
            "mailing_address": "optional",
            "goals": "optional",
            "city": "optional",
            "state": "optional",
            "country": "required",
            "honor_code": "required",
            "confirm_email": "required",
        },
        REGISTRATION_FIELD_ORDER=[
            "name",
            "username",
            "email",
            "confirm_email",
            "password",
            "first_name",
            "last_name",
            "city",
            "state",
            "country",
            "gender",
            "year_of_birth",
            "level_of_education",
            "company",
            "title",
            "job_title",
            "mailing_address",
            "goals",
            "honor_code",
            "terms_of_service",
            "specialty",
            "profession",
        ],
    )
    def test_field_order_override(self):
        response = self.client.get(self.url)
        self.assertHttpOK(response)

        # Verify that all fields render in the correct order
        form_desc = json.loads(response.content.decode('utf-8'))
        field_names = [field["name"] for field in form_desc["fields"]]
        self.assertEqual(field_names, [
            "name",
            "username",
            "email",
            "confirm_email",
            "password",
            "city",
            "state",
            "country",
            "gender",
            "year_of_birth",
            "level_of_education",
            "mailing_address",
            "goals",
            "honor_code",
        ])

    @override_settings(
        REGISTRATION_EXTRA_FIELDS={
            "level_of_education": "optional",
            "gender": "optional",
            "year_of_birth": "optional",
            "mailing_address": "optional",
            "goals": "optional",
            "city": "optional",
            "state": "optional",
            "country": "required",
            "honor_code": "required",
            "confirm_email": "required",
        },
        REGISTRATION_EXTENSION_FORM='openedx.core.djangoapps.user_api.tests.test_helpers.TestCaseForm',
        REGISTRATION_FIELD_ORDER=[
            "name",
            "confirm_email",
            "password",
            "first_name",
            "last_name",
            "gender",
            "year_of_birth",
            "level_of_education",
            "company",
            "title",
            "mailing_address",
            "goals",
            "honor_code",
            "terms_of_service",
        ],
    )
    def test_field_order_invalid_override(self):
        response = self.client.get(self.url)
        self.assertHttpOK(response)

        # Verify that all fields render in the correct order
        form_desc = json.loads(response.content.decode('utf-8'))
        field_names = [field["name"] for field in form_desc["fields"]]
        self.assertEqual(field_names, [
            "email",
            "name",
            "username",
            "password",
            "favorite_movie",
            "favorite_editor",
            "confirm_email",
            "city",
            "state",
            "country",
            "gender",
            "year_of_birth",
            "level_of_education",
            "mailing_address",
            "goals",
            "honor_code",
        ])

    def test_register(self):
        # Create a new registration
        response = self.client.post(self.url, {
            "email": self.EMAIL,
            "name": self.NAME,
            "username": self.USERNAME,
            "password": self.PASSWORD,
            "honor_code": "true",
        })
        self.assertHttpOK(response)
        self.assertIn(settings.EDXMKTG_LOGGED_IN_COOKIE_NAME, self.client.cookies)
        self.assertIn(settings.EDXMKTG_USER_INFO_COOKIE_NAME, self.client.cookies)

        user = User.objects.get(username=self.USERNAME)
        request = RequestFactory().get('/url')
        request.user = user
        account_settings = get_account_settings(request)[0]

        self.assertEqual(self.USERNAME, account_settings["username"])
        self.assertEqual(self.EMAIL, account_settings["email"])
        self.assertFalse(account_settings["is_active"])
        self.assertEqual(self.NAME, account_settings["name"])

        # Verify that we've been logged in
        # by trying to access a page that requires authentication
        response = self.client.get(reverse("dashboard"))
        self.assertHttpOK(response)

    @override_settings(REGISTRATION_EXTRA_FIELDS={
        "level_of_education": "optional",
        "gender": "optional",
        "year_of_birth": "optional",
        "mailing_address": "optional",
        "goals": "optional",
        "country": "required",
    })
    def test_register_with_profile_info(self):
        # Register, providing lots of demographic info
        response = self.client.post(self.url, {
            "email": self.EMAIL,
            "name": self.NAME,
            "username": self.USERNAME,
            "password": self.PASSWORD,
            "level_of_education": self.EDUCATION,
            "mailing_address": self.ADDRESS,
            "year_of_birth": self.YEAR_OF_BIRTH,
            "goals": self.GOALS,
            "country": self.COUNTRY,
            "honor_code": "true",
        })
        self.assertHttpOK(response)

        # Verify the user's account
        user = User.objects.get(username=self.USERNAME)
        request = RequestFactory().get('/url')
        request.user = user
        account_settings = get_account_settings(request)[0]

        self.assertEqual(account_settings["level_of_education"], self.EDUCATION)
        self.assertEqual(account_settings["mailing_address"], self.ADDRESS)
        self.assertEqual(account_settings["year_of_birth"], int(self.YEAR_OF_BIRTH))
        self.assertEqual(account_settings["goals"], self.GOALS)
        self.assertEqual(account_settings["country"], self.COUNTRY)

    @override_settings(REGISTRATION_EXTENSION_FORM='openedx.core.djangoapps.user_api.tests.test_helpers.TestCaseForm')
    @mock.patch('openedx.core.djangoapps.user_api.tests.test_helpers.TestCaseForm.DUMMY_STORAGE', new_callable=dict)
    @mock.patch(
        'openedx.core.djangoapps.user_api.tests.test_helpers.DummyRegistrationExtensionModel',
    )
    def test_with_extended_form(self, dummy_model, storage_dict):
        dummy_model_instance = mock.Mock()
        dummy_model.return_value = dummy_model_instance
        # Create a new registration
        self.assertEqual(storage_dict, {})
        response = self.client.post(self.url, {
            "email": self.EMAIL,
            "name": self.NAME,
            "username": self.USERNAME,
            "password": self.PASSWORD,
            "honor_code": "true",
            "favorite_movie": "Inception",
            "favorite_editor": "cat",
        })
        self.assertHttpOK(response)
        self.assertIn(settings.EDXMKTG_LOGGED_IN_COOKIE_NAME, self.client.cookies)
        self.assertIn(settings.EDXMKTG_USER_INFO_COOKIE_NAME, self.client.cookies)

        user = User.objects.get(username=self.USERNAME)
        request = RequestFactory().get('/url')
        request.user = user
        account_settings = get_account_settings(request)[0]

        self.assertEqual(self.USERNAME, account_settings["username"])
        self.assertEqual(self.EMAIL, account_settings["email"])
        self.assertFalse(account_settings["is_active"])
        self.assertEqual(self.NAME, account_settings["name"])

        self.assertEqual(storage_dict, {'favorite_movie': "Inception", "favorite_editor": "cat"})
        self.assertEqual(dummy_model_instance.user, user)

        # Verify that we've been logged in
        # by trying to access a page that requires authentication
        response = self.client.get(reverse("dashboard"))
        self.assertHttpOK(response)

    def test_activation_email(self):
        # Register, which should trigger an activation email
        response = self.client.post(self.url, {
            "email": self.EMAIL,
            "name": self.NAME,
            "username": self.USERNAME,
            "password": self.PASSWORD,
            "honor_code": "true",
        })
        self.assertHttpOK(response)

        # Verify that the activation email was sent
        self.assertEqual(len(mail.outbox), 1)
        sent_email = mail.outbox[0]
        self.assertEqual(sent_email.to, [self.EMAIL])
        self.assertEqual(
            sent_email.subject,
            u"Action Required: Activate your {platform} account".format(platform=settings.PLATFORM_NAME)
        )
        self.assertIn(
            u"high-quality {platform} courses".format(platform=settings.PLATFORM_NAME),
            sent_email.body
        )

    @ddt.data(
        {"email": ""},
        {"email": "invalid"},
        {"name": ""},
        {"username": ""},
        {"username": "a"},
        {"password": ""},
    )
    def test_register_invalid_input(self, invalid_fields):
        # Initially, the field values are all valid
        data = {
            "email": self.EMAIL,
            "name": self.NAME,
            "username": self.USERNAME,
            "password": self.PASSWORD,
        }

        # Override the valid fields, making the input invalid
        data.update(invalid_fields)

        # Attempt to create the account, expecting an error response
        response = self.client.post(self.url, data)
        self.assertHttpBadRequest(response)

    @override_settings(REGISTRATION_EXTRA_FIELDS={"country": "required"})
    @ddt.data("email", "name", "username", "password", "country")
    def test_register_missing_required_field(self, missing_field):
        data = {
            "email": self.EMAIL,
            "name": self.NAME,
            "username": self.USERNAME,
            "password": self.PASSWORD,
            "country": self.COUNTRY,
        }

        del data[missing_field]

        # Send a request missing a field
        response = self.client.post(self.url, data)
        self.assertHttpBadRequest(response)

    def test_register_duplicate_email(self):
        # Register the first user
        response = self.client.post(self.url, {
            "email": self.EMAIL,
            "name": self.NAME,
            "username": self.USERNAME,
            "password": self.PASSWORD,
            "honor_code": "true",
        })
        self.assertHttpOK(response)

        # Try to create a second user with the same email address
        response = self.client.post(self.url, {
            "email": self.EMAIL,
            "name": "Someone Else",
            "username": "someone_else",
            "password": self.PASSWORD,
            "honor_code": "true",
        })
        self.assertEqual(response.status_code, 409)
        response_json = json.loads(response.content.decode('utf-8'))
        self.assertDictEqual(
            response_json,
            {
                "success": False,
                "email": [{
                    "user_message": (
                        u"It looks like {} belongs to an existing account. "
                        "Try again with a different email address."
                    ).format(
                        self.EMAIL
                    )
                }]
            }
        )

    def test_register_duplicate_username(self):
        # Register the first user
        response = self.client.post(self.url, {
            "email": self.EMAIL,
            "name": self.NAME,
            "username": self.USERNAME,
            "password": self.PASSWORD,
            "honor_code": "true",
        })
        self.assertHttpOK(response)

        # Try to create a second user with the same username
        response = self.client.post(self.url, {
            "email": "someone+else@example.com",
            "name": "Someone Else",
            "username": self.USERNAME,
            "password": self.PASSWORD,
            "honor_code": "true",
        })
        self.assertEqual(response.status_code, 409)
        response_json = json.loads(response.content.decode('utf-8'))
        self.assertDictEqual(
            response_json,
            {
                "success": False,
                "username": [{
                    "user_message": (
                        u"It looks like {} belongs to an existing account. "
                        "Try again with a different username."
                    ).format(
                        self.USERNAME
                    )
                }]
            }
        )

    def test_register_duplicate_username_and_email(self):
        # Register the first user
        response = self.client.post(self.url, {
            "email": self.EMAIL,
            "name": self.NAME,
            "username": self.USERNAME,
            "password": self.PASSWORD,
            "honor_code": "true",
        })
        self.assertHttpOK(response)

        # Try to create a second user with the same username
        response = self.client.post(self.url, {
            "email": self.EMAIL,
            "name": "Someone Else",
            "username": self.USERNAME,
            "password": self.PASSWORD,
            "honor_code": "true",
        })
        self.assertEqual(response.status_code, 409)
        response_json = json.loads(response.content.decode('utf-8'))
        self.assertDictEqual(
            response_json,
            {
                "success": False,
                "username": [{
                    "user_message": (
                        u"It looks like {} belongs to an existing account. "
                        "Try again with a different username."
                    ).format(
                        self.USERNAME
                    )
                }],
                "email": [{
                    "user_message": (
                        u"It looks like {} belongs to an existing account. "
                        "Try again with a different email address."
                    ).format(
                        self.EMAIL
                    )
                }]
            }
        )

    @override_settings(REGISTRATION_EXTRA_FIELDS={"honor_code": "hidden", "terms_of_service": "hidden"})
    def test_register_hidden_honor_code_and_terms_of_service(self):
        response = self.client.post(self.url, {
            "email": self.EMAIL,
            "name": self.NAME,
            "username": self.USERNAME,
            "password": self.PASSWORD,
        })
        self.assertHttpOK(response)

    def test_missing_fields(self):
        response = self.client.post(
            self.url,
            {
                "email": self.EMAIL,
                "name": self.NAME,
                "honor_code": "true",
            }
        )
        self.assertEqual(response.status_code, 400)
        response_json = json.loads(response.content.decode('utf-8'))
        self.assertDictEqual(
            response_json,
            {
                u"success": False,
                u"username": [{u"user_message": USERNAME_BAD_LENGTH_MSG}],
                u"password": [{u"user_message": u"This field is required."}],
            }
        )

    def test_country_overrides(self):
        """Test that overridden countries are available in country list."""
        # Retrieve the registration form description
        with override_settings(REGISTRATION_EXTRA_FIELDS={"country": "required"}):
            response = self.client.get(self.url)
            self.assertHttpOK(response)

        self.assertContains(response, 'Kosovo')

    def test_create_account_not_allowed(self):
        """
        Test case to check user creation is forbidden when ALLOW_PUBLIC_ACCOUNT_CREATION feature flag is turned off
        """
        def _side_effect_for_get_value(value, default=None):
            """
            returns a side_effect with given return value for a given value
            """
            if value == 'ALLOW_PUBLIC_ACCOUNT_CREATION':
                return False
            else:
                return get_value(value, default)

        with mock.patch('openedx.core.djangoapps.site_configuration.helpers.get_value') as mock_get_value:
            mock_get_value.side_effect = _side_effect_for_get_value
            response = self.client.post(self.url, {"email": self.EMAIL, "username": self.USERNAME})
            self.assertEqual(response.status_code, 403)

    def _assert_fields_match(self, actual_field, expected_field):
        """
        Assert that the actual field and the expected field values match.
        """
        self.assertIsNot(
            actual_field, None,
            msg=u"Could not find field {name}".format(name=expected_field["name"])
        )

        for key in expected_field:
            self.assertEqual(
                actual_field[key], expected_field[key],
                msg=u"Expected {expected} for {key} but got {actual} instead".format(
                    key=key,
                    actual=actual_field[key],
                    expected=expected_field[key]
                )
            )

    def _populate_always_present_fields(self, field):
        """
        Populate field dictionary with keys and values that are always present.
        """
        defaults = [
            ("label", ""),
            ("instructions", ""),
            ("placeholder", ""),
            ("defaultValue", ""),
            ("restrictions", {}),
            ("errorMessages", {}),
        ]
        field.update({
            key: value
            for key, value in defaults if key not in field
        })

    def _assert_reg_field(self, extra_fields_setting, expected_field):
        """Retrieve the registration form description from the server and
        verify that it contains the expected field.

        Args:
            extra_fields_setting (dict): Override the Django setting controlling
                which extra fields are displayed in the form.

            expected_field (dict): The field definition we expect to find in the form.

        Raises:
            AssertionError

        """
        # Add in fields that are always present
        self._populate_always_present_fields(expected_field)

        # Retrieve the registration form description
        with override_settings(REGISTRATION_EXTRA_FIELDS=extra_fields_setting):
            response = self.client.get(self.url)
            self.assertHttpOK(response)

        # Verify that the form description matches what we'd expect
        form_desc = json.loads(response.content.decode('utf-8'))

        actual_field = None
        for field in form_desc["fields"]:
            if field["name"] == expected_field["name"]:
                actual_field = field
                break

        self._assert_fields_match(actual_field, expected_field)

    def _assert_password_field_hidden(self, field_settings):
        self._assert_reg_field(field_settings, {
            "name": "password",
            "type": "hidden",
            "required": False
        })

    def _assert_social_auth_provider_present(self, field_settings, backend):
        self._assert_reg_field(field_settings, {
            "name": "social_auth_provider",
            "type": "hidden",
            "required": False,
            "defaultValue": backend.name
        })


@httpretty.activate
@ddt.ddt
class ThirdPartyRegistrationTestMixin(ThirdPartyOAuthTestMixin, CacheIsolationTestCase):
    """
    Tests for the User API registration endpoint with 3rd party authentication.
    """
    CREATE_USER = False

    ENABLED_CACHES = ['default']

    __test__ = False

    def setUp(self):
        super(ThirdPartyRegistrationTestMixin, self).setUp()
        self.url = reverse('user_api_registration')

    def tearDown(self):
        super(ThirdPartyRegistrationTestMixin, self).tearDown()
        Partial.objects.all().delete()

    def data(self, user=None):
        """Returns the request data for the endpoint."""
        return {
            "provider": self.BACKEND,
            "access_token": self.access_token,
            "client_id": self.client_id,
            "honor_code": "true",
            "country": "US",
            "username": user.username if user else "test_username",
            "name": user.first_name if user else "test name",
            "email": user.email if user else "test@test.com"
        }

    def _assert_existing_user_error(self, response):
        """Assert that the given response was an error with the given status_code and error code."""
        self.assertEqual(response.status_code, 409)
        errors = json.loads(response.content.decode('utf-8'))
        for conflict_attribute in ["username", "email"]:
            self.assertIn(conflict_attribute, errors)
            self.assertIn("belongs to an existing account", errors[conflict_attribute][0]["user_message"])

    def _assert_access_token_error(self, response, expected_error_message):
        """Assert that the given response was an error for the access_token field with the given error message."""
        self.assertEqual(response.status_code, 400)
        response_json = json.loads(response.content.decode('utf-8'))
        self.assertDictEqual(
            response_json,
            {
                "success": False,
                "access_token": [{"user_message": expected_error_message}],
            }
        )

    def _assert_third_party_session_expired_error(self, response, expected_error_message):
        """Assert that given response is an error due to third party session expiry"""
        self.assertEqual(response.status_code, 400)
        response_json = json.loads(response.content.decode('utf-8'))
        self.assertDictEqual(
            response_json,
            {
                "success": False,
                "session_expired": [{"user_message": expected_error_message}],
            }
        )

    def _verify_user_existence(self, user_exists, social_link_exists, user_is_active=None, username=None):
        """Verifies whether the user object exists."""
        users = User.objects.filter(username=(username if username else "test_username"))
        self.assertEquals(users.exists(), user_exists)
        if user_exists:
            self.assertEquals(users[0].is_active, user_is_active)
            self.assertEqual(
                UserSocialAuth.objects.filter(user=users[0], provider=self.BACKEND).exists(),
                social_link_exists
            )
        else:
            self.assertEquals(UserSocialAuth.objects.count(), 0)

    def test_success(self):
        self._verify_user_existence(user_exists=False, social_link_exists=False)

        self._setup_provider_response(success=True)
        response = self.client.post(self.url, self.data())
        self.assertEqual(response.status_code, 200)

        self._verify_user_existence(user_exists=True, social_link_exists=True, user_is_active=False)

    def test_unlinked_active_user(self):
        user = UserFactory()
        response = self.client.post(self.url, self.data(user))
        self._assert_existing_user_error(response)
        self._verify_user_existence(
            user_exists=True, social_link_exists=False, user_is_active=True, username=user.username
        )

    def test_unlinked_inactive_user(self):
        user = UserFactory(is_active=False)
        response = self.client.post(self.url, self.data(user))
        self._assert_existing_user_error(response)
        self._verify_user_existence(
            user_exists=True, social_link_exists=False, user_is_active=False, username=user.username
        )

    def test_user_already_registered(self):
        self._setup_provider_response(success=True)
        user = UserFactory()
        UserSocialAuth.objects.create(user=user, provider=self.BACKEND, uid=self.social_uid)
        response = self.client.post(self.url, self.data(user))
        self._assert_existing_user_error(response)
        self._verify_user_existence(
            user_exists=True, social_link_exists=True, user_is_active=True, username=user.username
        )

    def test_social_user_conflict(self):
        self._setup_provider_response(success=True)
        user = UserFactory()
        UserSocialAuth.objects.create(user=user, provider=self.BACKEND, uid=self.social_uid)
        response = self.client.post(self.url, self.data())
        self._assert_access_token_error(response, "The provided access_token is already associated with another user.")
        self._verify_user_existence(
            user_exists=True, social_link_exists=True, user_is_active=True, username=user.username
        )

    def test_invalid_token(self):
        self._setup_provider_response(success=False)
        response = self.client.post(self.url, self.data())
        self._assert_access_token_error(response, "The provided access_token is not valid.")
        self._verify_user_existence(user_exists=False, social_link_exists=False)

    def test_missing_token(self):
        data = self.data()
        data.pop("access_token")
        response = self.client.post(self.url, data)
        self._assert_access_token_error(
            response,
            u"An access_token is required when passing value ({}) for provider.".format(self.BACKEND)
        )
        self._verify_user_existence(user_exists=False, social_link_exists=False)

    def test_expired_pipeline(self):

        """
        Test that there is an error and account is not created
        when request is made for account creation using third (Google, Facebook etc) party with pipeline
        getting expired using browser (not mobile application).

        NOTE: We are NOT using actual pipeline here so pipeline is always expired in this environment.
        we don't have to explicitly expire pipeline.

        """

        data = self.data()
        # provider is sent along request when request is made from mobile application
        data.pop("provider")
        # to identify that request is made using browser
        data.update({"social_auth_provider": "Google"})
        response = self.client.post(self.url, data)
        self._assert_third_party_session_expired_error(
            response,
            u"Registration using {provider} has timed out.".format(provider="Google")
        )
        self._verify_user_existence(user_exists=False, social_link_exists=False)


@skipUnless(settings.FEATURES.get("ENABLE_THIRD_PARTY_AUTH"), "third party auth not enabled")
class TestFacebookRegistrationView(
    ThirdPartyRegistrationTestMixin, ThirdPartyOAuthTestMixinFacebook, TransactionTestCase
):
    """Tests the User API registration endpoint with Facebook authentication."""
    __test__ = True

    def test_social_auth_exception(self):
        """
        According to the do_auth method in social_core.backends.facebook.py,
        the Facebook API sometimes responds back a JSON with just False as value.
        """
        self._setup_provider_response_with_body(200, json.dumps("false"))
        response = self.client.post(self.url, self.data())
        self._assert_access_token_error(response, "The provided access_token is not valid.")
        self._verify_user_existence(user_exists=False, social_link_exists=False)


@skipUnless(settings.FEATURES.get("ENABLE_THIRD_PARTY_AUTH"), "third party auth not enabled")
class TestGoogleRegistrationView(
    ThirdPartyRegistrationTestMixin, ThirdPartyOAuthTestMixinGoogle, TransactionTestCase
):
    """Tests the User API registration endpoint with Google authentication."""
    __test__ = True
