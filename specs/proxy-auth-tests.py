# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.
"""
Design contract for ProxyAuthMiddleware — reference document only.

Canonical, runnable test suites:
    apps/api/plane/authentication/tests/test_proxy_auth.py       (middleware)
    apps/api/plane/authentication/tests/test_proxy_auth_core.py  (core utils)

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
