# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

from django.conf import settings
from django.contrib.auth import login
from django.db import IntegrityError

from plane.db.models import Profile, User

_DEFAULT_BYPASS_PATHS = ["/god-mode", "/api/instances"]


class ProxyAuthMiddleware:
    """
    Authenticate requests forwarded through oauth2-proxy.

    oauth2-proxy sets X-Auth-Request-Email and X-Auth-Request-User on every
    request that has passed OIDC validation. This middleware reads those
    headers, finds or creates the corresponding Plane user, and establishes a
    native Django session — so the rest of the app sees a fully authenticated
    request.user just as it would after a normal login.

    Bypass paths (god-mode, instances admin) are skipped entirely; the session
    check means returning users pay zero DB cost on subsequent requests.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.bypass_paths = getattr(settings, "MPASS_BYPASS_PATHS", _DEFAULT_BYPASS_PATHS)

    def __call__(self, request):
        # Layer 2 session already valid — nothing to do.
        if request.user.is_authenticated:
            return self.get_response(request)

        # Bypass paths use their own auth (god-mode local login, instance admin).
        if any(request.path.startswith(p) for p in self.bypass_paths):
            return self.get_response(request)

        email = request.META.get("HTTP_X_AUTH_REQUEST_EMAIL")
        if not email:
            return self.get_response(request)

        email = email.strip().lower()
        sub = request.META.get("HTTP_X_AUTH_REQUEST_USER")
        username = sub or email

        user = self._resolve_user(email, username)
        login(request, user, backend="django.contrib.auth.backends.ModelBackend")
        return self.get_response(request)

    def _resolve_user(self, email, username):
        try:
            user, created = User.objects.get_or_create(
                email=email,
                defaults={"username": username},
            )
        except IntegrityError:
            # A concurrent request already created the user between our lookup
            # and insert. Fall back to a plain get.
            user = User.objects.get(email=email)
            created = False

        if created:
            user.set_unusable_password()
            user.is_password_autoset = True
            user.is_email_verified = True
            user.save(update_fields=["password", "is_password_autoset", "is_email_verified"])
            Profile.objects.create(user=user)

        return user
