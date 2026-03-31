# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

from uuid import uuid4

from django.conf import settings
from django.db import IntegrityError

from plane.authentication.utils.login import user_login
from plane.db.models import Profile, User

_DEFAULT_BYPASS_PATHS = ["/god-mode", "/api/instances"]

# Security note: header spoofing is not a concern on protected routes because
# Traefik ForwardAuth overwrites X-Auth-Request-* headers before they reach
# the app. Bypass paths never run this middleware, so spoofed headers there
# have no effect either.


class ProxyAuthMiddleware:
    """
    Authenticate requests forwarded through oauth2-proxy.

    oauth2-proxy sets X-Auth-Request-Email and X-Auth-Request-User on every
    request that has passed OIDC validation. This middleware reads those
    headers, finds or creates the corresponding Plane user, and establishes a
    native Django session — so the rest of the app sees a fully authenticated
    request.user just as it would after a normal login.

    Set MPASS_PROXY_AUTH_ENABLED = False in settings to disable entirely.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.enabled = getattr(settings, "MPASS_PROXY_AUTH_ENABLED", True)
        bypass = getattr(settings, "MPASS_BYPASS_PATHS", _DEFAULT_BYPASS_PATHS)
        self.bypass_paths = [bypass] if isinstance(bypass, str) else bypass

    def __call__(self, request):
        if not self.enabled:
            return self.get_response(request)

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
        user = self._resolve_user(email)

        # Respect deactivated accounts — mPass authentication does not
        # override an explicit Plane account suspension.
        if not user.is_active:
            return self.get_response(request)

        user_login(request=request, user=user, is_app=True)
        return self.get_response(request)

    def _resolve_user(self, email):
        try:
            user, created = User.objects.get_or_create(
                email=email,
                defaults={"username": uuid4().hex},
            )
        except IntegrityError:
            # A concurrent request raced us to the insert. The collision could
            # be on email or username — fall back to get() by email, and re-raise
            # if the user still doesn't exist (a different integrity violation).
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                raise
            created = False

        if created:
            user.set_unusable_password()
            user.is_password_autoset = True
            user.is_email_verified = True
            user.save(update_fields=["password", "is_password_autoset", "is_email_verified"])
            Profile.objects.get_or_create(user=user)

        return user
