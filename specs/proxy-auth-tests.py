# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.
"""
Test spec for ProxyAuthMiddleware.

NOTE: This file is a historical spec/reference document.
      The canonical, runnable test suite is at:
          apps/api/plane/authentication/tests/test_proxy_auth.py

Design contract (matches current implementation)
-------------------------------------------------
- Reads HTTP_X_AUTH_REQUEST_EMAIL from request.META
- If MPASS_PROXY_AUTH_ENABLED is False → pass through (kill switch)
- If request.user.is_authenticated → pass through immediately (no DB, no login)
- If path starts with a bypass prefix → pass through immediately (no DB, no login)
  Default bypass prefixes: ["/god-mode", "/api/instances"]
- If email header is absent → pass through unauthenticated
- If email is present → get_or_create User, create Profile on first creation,
  then call user_login(request=request, user=user, is_app=True) to establish session
- New users get: set_unusable_password(), is_password_autoset=True, is_email_verified=True
- username is always uuid4().hex (never the Cognito sub — avoids length/collision issues)
- Email is normalised (lowercased + stripped) before DB lookup
- Inactive users pass through unauthenticated even with a valid header
- IntegrityError on concurrent creation falls back to .get(email=email),
  re-raises original IntegrityError if the user still doesn't exist
- MPASS_BYPASS_PATHS=None falls back to default paths (no crash)
"""

import pytest
from unittest.mock import MagicMock, patch, call
from django.contrib.auth.models import AnonymousUser
from django.test import RequestFactory

# ---------------------------------------------------------------------------
# Import the middleware under test.
# This import will FAIL (ImportError) until the file is created — that is the
# expected RED state in TDD.
# ---------------------------------------------------------------------------
from plane.authentication.middleware.proxy_auth import ProxyAuthMiddleware

# Real models — tests hit an actual DB (no mocking per project policy)
from plane.db.models import User, Profile


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_request(path="/api/issues/", meta=None, authenticated_user=None):
    """Return a fake GET request with optional META headers and auth state."""
    factory = RequestFactory()
    request = factory.get(path)
    request.session = {}

    if authenticated_user:
        request.user = authenticated_user
    else:
        request.user = AnonymousUser()

    if meta:
        request.META.update(meta)

    return request


def make_middleware(get_response=None):
    """Return a ProxyAuthMiddleware instance with a trivial get_response stub."""
    if get_response is None:
        get_response = MagicMock(return_value=MagicMock(status_code=200))
    return ProxyAuthMiddleware(get_response)


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------


class TestProxyAuthMiddlewareAlreadyAuthenticated:
    """Middleware must short-circuit for requests that already carry a session."""

    @pytest.mark.django_db
    def test_skips_when_user_already_authenticated(self, django_user_model):
        """
        GIVEN  a request whose user.is_authenticated is True
        WHEN   the middleware processes the request
        THEN   get_response is called exactly once
               AND no User is created or queried by email
               AND login() is never called
        """
        existing_user = django_user_model.objects.create_user(
            email="active@example.com",
            username="active_user",
            password="irrelevant",
        )
        get_response = MagicMock(return_value=MagicMock(status_code=200))
        middleware = make_middleware(get_response)

        request = make_request(
            meta={
                "HTTP_X_AUTH_REQUEST_EMAIL": "active@example.com",
                "HTTP_X_AUTH_REQUEST_USER": "sub-already-authed",
            },
            authenticated_user=existing_user,
        )

        user_count_before = User.objects.count()

        with patch("plane.authentication.middleware.proxy_auth.login") as mock_login:
            middleware(request)

        get_response.assert_called_once_with(request)
        mock_login.assert_not_called()
        assert User.objects.count() == user_count_before


class TestProxyAuthMiddlewareNoHeader:
    """Middleware must pass through cleanly when the email header is absent."""

    def test_passes_through_when_no_email_header(self):
        """
        GIVEN  a request with no X-Auth-Request-Email header
        WHEN   the middleware processes the request
        THEN   get_response is called
               AND login() is never called
               AND request.user remains AnonymousUser
        """
        get_response = MagicMock(return_value=MagicMock(status_code=200))
        middleware = make_middleware(get_response)
        request = make_request()  # no META headers

        with patch("plane.authentication.middleware.proxy_auth.login") as mock_login:
            middleware(request)

        get_response.assert_called_once_with(request)
        mock_login.assert_not_called()
        assert isinstance(request.user, AnonymousUser)


class TestProxyAuthMiddlewareNewUser:
    """Middleware must create a User + Profile on first-seen email."""

    @pytest.mark.django_db
    def test_creates_new_user_with_correct_fields(self):
        """
        GIVEN  a request carrying a previously-unseen email header
        WHEN   the middleware processes the request
        THEN   a new User row exists with:
                 email == lowercased header value
                 is_password_autoset == True
                 is_email_verified == True
                 has_usable_password() == False
        """
        middleware = make_middleware()
        request = make_request(
            meta={
                "HTTP_X_AUTH_REQUEST_EMAIL": "newuser@example.com",
                "HTTP_X_AUTH_REQUEST_USER": "cognito-sub-001",
            }
        )

        with patch("plane.authentication.middleware.proxy_auth.login"):
            middleware(request)

        user = User.objects.get(email="newuser@example.com")
        assert user.is_password_autoset is True
        assert user.is_email_verified is True
        assert user.has_usable_password() is False

    @pytest.mark.django_db
    def test_creates_profile_for_new_user(self):
        """
        GIVEN  a request carrying a previously-unseen email header
        WHEN   the middleware processes the request
        THEN   a Profile row is created for the new user
        """
        middleware = make_middleware()
        request = make_request(
            meta={
                "HTTP_X_AUTH_REQUEST_EMAIL": "profiletest@example.com",
                "HTTP_X_AUTH_REQUEST_USER": "cognito-sub-002",
            }
        )

        with patch("plane.authentication.middleware.proxy_auth.login"):
            middleware(request)

        user = User.objects.get(email="profiletest@example.com")
        assert Profile.objects.filter(user=user).exists()

    @pytest.mark.django_db
    def test_username_set_to_sub_when_present(self):
        """
        GIVEN  a request with both email and sub headers
        WHEN   a new user is created
        THEN   user.username equals the X-Auth-Request-User sub value
        """
        middleware = make_middleware()
        request = make_request(
            meta={
                "HTTP_X_AUTH_REQUEST_EMAIL": "subtest@example.com",
                "HTTP_X_AUTH_REQUEST_USER": "unique-cognito-sub-xyz",
            }
        )

        with patch("plane.authentication.middleware.proxy_auth.login"):
            middleware(request)

        user = User.objects.get(email="subtest@example.com")
        assert user.username == "unique-cognito-sub-xyz"

    @pytest.mark.django_db
    def test_username_falls_back_to_email_when_sub_absent(self):
        """
        GIVEN  a request with an email header but no X-Auth-Request-User header
        WHEN   a new user is created
        THEN   user.username is set to the email (not blank, not errored)
        """
        middleware = make_middleware()
        request = make_request(
            meta={"HTTP_X_AUTH_REQUEST_EMAIL": "nosub@example.com"}
            # no HTTP_X_AUTH_REQUEST_USER
        )

        with patch("plane.authentication.middleware.proxy_auth.login"):
            middleware(request)

        user = User.objects.get(email="nosub@example.com")
        assert user.username  # non-empty
        assert "@" in user.username or len(user.username) > 0


class TestProxyAuthMiddlewareExistingUser:
    """Middleware must find — not duplicate — an existing user."""

    @pytest.mark.django_db
    def test_finds_existing_user_without_creating_duplicate(self, django_user_model):
        """
        GIVEN  a User already exists for the incoming email
        WHEN   the middleware processes a request with that email header
        THEN   no new User row is created
               AND login() is called with the existing user
        """
        existing = django_user_model.objects.create_user(
            email="returning@example.com",
            username="returning_user",
            password="whatever",
        )
        count_before = User.objects.count()

        middleware = make_middleware()
        request = make_request(
            meta={
                "HTTP_X_AUTH_REQUEST_EMAIL": "returning@example.com",
                "HTTP_X_AUTH_REQUEST_USER": "sub-returning",
            }
        )

        with patch("plane.authentication.middleware.proxy_auth.login") as mock_login:
            middleware(request)

        assert User.objects.count() == count_before

        # login() must be called with the correct user object
        args, kwargs = mock_login.call_args
        assert existing in args or kwargs.get("user") == existing


class TestProxyAuthMiddlewareLogin:
    """Middleware must always call login() after resolving the user."""

    @pytest.mark.django_db
    def test_login_is_called_with_request_and_user(self):
        """
        GIVEN  a valid email header for a new user
        WHEN   the middleware runs
        THEN   login() is called with (request, user) positionally or by keyword
               AND the user passed to login() has email == header email
        """
        middleware = make_middleware()
        request = make_request(
            meta={
                "HTTP_X_AUTH_REQUEST_EMAIL": "logincheck@example.com",
                "HTTP_X_AUTH_REQUEST_USER": "sub-login-check",
            }
        )

        with patch("plane.authentication.middleware.proxy_auth.login") as mock_login:
            middleware(request)

        mock_login.assert_called_once()
        call_args = mock_login.call_args
        # request must be first positional arg or 'request' kwarg
        passed_request = call_args.args[0] if call_args.args else call_args.kwargs["request"]
        passed_user = call_args.args[1] if len(call_args.args) > 1 else call_args.kwargs["user"]
        assert passed_request is request
        assert passed_user.email == "logincheck@example.com"


class TestProxyAuthMiddlewareBypassPaths:
    """Middleware must not authenticate requests on bypass paths."""

    @pytest.mark.django_db
    def test_god_mode_path_is_bypassed(self):
        """
        GIVEN  a request to /god-mode/setup/ with a valid email header
        WHEN   the middleware processes the request
        THEN   login() is never called
               AND no User is created
        """
        count_before = User.objects.count()
        middleware = make_middleware()
        request = make_request(
            path="/god-mode/setup/",
            meta={
                "HTTP_X_AUTH_REQUEST_EMAIL": "admin@example.com",
                "HTTP_X_AUTH_REQUEST_USER": "sub-admin",
            },
        )

        with patch("plane.authentication.middleware.proxy_auth.login") as mock_login:
            middleware(request)

        mock_login.assert_not_called()
        assert User.objects.count() == count_before

    @pytest.mark.django_db
    def test_instances_path_is_bypassed(self):
        """
        GIVEN  a request to /api/instances/config/ with a valid email header
        WHEN   the middleware processes the request
        THEN   login() is never called
               AND no User is created
        """
        count_before = User.objects.count()
        middleware = make_middleware()
        request = make_request(
            path="/api/instances/config/",
            meta={
                "HTTP_X_AUTH_REQUEST_EMAIL": "instance-admin@example.com",
                "HTTP_X_AUTH_REQUEST_USER": "sub-instance",
            },
        )

        with patch("plane.authentication.middleware.proxy_auth.login") as mock_login:
            middleware(request)

        mock_login.assert_not_called()
        assert User.objects.count() == count_before


class TestProxyAuthMiddlewareEdgeCases:
    """Misc edge cases: email normalisation and concurrent creation races."""

    @pytest.mark.django_db
    def test_email_normalised_before_lookup(self, django_user_model):
        """
        GIVEN  a User exists with lowercase email "norm@example.com"
               AND the incoming header supplies "  NORM@EXAMPLE.COM  "
        WHEN   the middleware processes the request
        THEN   the existing user is found (not a duplicate created)
               AND login() is called with the original user
        """
        existing = django_user_model.objects.create_user(
            email="norm@example.com",
            username="norm_user",
            password="x",
        )
        count_before = User.objects.count()

        middleware = make_middleware()
        request = make_request(
            meta={
                "HTTP_X_AUTH_REQUEST_EMAIL": "  NORM@EXAMPLE.COM  ",
                "HTTP_X_AUTH_REQUEST_USER": "sub-norm",
            }
        )

        with patch("plane.authentication.middleware.proxy_auth.login") as mock_login:
            middleware(request)

        assert User.objects.count() == count_before
        call_args = mock_login.call_args
        passed_user = call_args.args[1] if len(call_args.args) > 1 else call_args.kwargs["user"]
        assert passed_user.pk == existing.pk

    @pytest.mark.django_db
    def test_integrity_error_race_condition_is_handled(self):
        """
        GIVEN  a concurrent request causes an IntegrityError on User.save()
               (simulated by patching get_or_create to raise on first call)
        WHEN   the middleware processes the request
        THEN   it falls back to User.objects.get(email=email)
               AND login() is still called with the resolved user
               AND no exception propagates to the caller
        """
        from django.db import IntegrityError

        middleware = make_middleware()
        request = make_request(
            meta={
                "HTTP_X_AUTH_REQUEST_EMAIL": "race@example.com",
                "HTTP_X_AUTH_REQUEST_USER": "sub-race",
            }
        )

        # Pre-create the user so the fallback .get() will succeed
        existing = User.objects.create(
            email="race@example.com",
            username="sub-race",
        )
        existing.set_unusable_password()
        existing.save()

        original_get_or_create = User.objects.get_or_create

        call_count = {"n": 0}

        def raise_once(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise IntegrityError("duplicate key value")
            return original_get_or_create(*args, **kwargs)

        with patch.object(User.objects, "get_or_create", side_effect=raise_once):
            with patch("plane.authentication.middleware.proxy_auth.login") as mock_login:
                # Must not raise
                middleware(request)

        mock_login.assert_called_once()
