# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

# WARNING: DEBUG ONLY — never deploy this middleware in production.
# Add to MIDDLEWARE in local.py (not common.py) BEFORE ProxyAuthMiddleware.
# It simulates the headers that oauth2-proxy injects so you can test the full
# auth flow locally without running Traefik + oauth2-proxy.

from django.conf import settings


class FakeProxyHeadersMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if settings.DEBUG:
            request.META.setdefault("HTTP_X_AUTH_REQUEST_EMAIL", "testuser@example.com")
            request.META.setdefault("HTTP_X_AUTH_REQUEST_USER", "fake-sub-12345")
        return self.get_response(request)
