# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

from uuid import uuid4

from django.conf import settings
from django.db import IntegrityError

from plane.authentication.utils.login import user_login
from plane.db.models import Profile, User

from .proxy_auth_core import (
    NEW_USER_FLAGS,
    coerce_bypass_paths,
    is_bypass_path,
    normalise_email,
)

# Security note: header spoofing is not a concern on protected routes because
# Traefik ForwardAuth overwrites X-Auth-Request-* headers before they reach
# the app. Bypass paths never run this middleware, so spoofed headers there
# have no effect either.


class ProxyAuthMiddleware:
    """
    Django adapter for mPass proxy authentication.

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
        self.bypass_paths = coerce_bypass_paths(
            getattr(settings, "MPASS_BYPASS_PATHS", None)
        )

    def __call__(self, request):
        if not self.enabled:
            return self.get_response(request)

        # Layer 2 session already valid — nothing to do.
        if request.user.is_authenticated:
            return self.get_response(request)

        # Bypass paths use their own auth (god-mode local login, instance admin).
        if is_bypass_path(request.path, self.bypass_paths):
            return self.get_response(request)

        email = request.META.get("HTTP_X_AUTH_REQUEST_EMAIL") or request.META.get("HTTP_X_FORWARDED_EMAIL")
        if not email:
            return self.get_response(request)

        user = self._resolve_user(normalise_email(email))

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
        except IntegrityError as exc:
            # A concurrent request raced us to the insert. The collision could
            # be on email or username — fall back to get() by email, and re-raise
            # the original IntegrityError if the user still doesn't exist
            # (meaning a different constraint was violated).
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                raise exc
            created = False

        if created:
            user.set_unusable_password()
            for field, value in NEW_USER_FLAGS.items():
                setattr(user, field, value)
            # NEW_USER_FLAGS keys intentionally drive update_fields — adding a
            # flag to the core dict automatically includes it in the save().
            user.save(update_fields=["password", *NEW_USER_FLAGS.keys()])
            Profile.objects.get_or_create(user=user)

        return user
