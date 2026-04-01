# CLAUDE.md — mPass OIDC Integration Project Context

## Project Overview

We are integrating mPass (an AWS Cognito-based OIDC identity provider) as the sole login method across four open-source apps: Plane, Penpot, Outline, and SurfSense. These apps sit behind a Traefik reverse proxy. We use oauth2-proxy as a centralized authentication gateway.

## Architecture

```
User Browser
    ↓
Traefik (reverse proxy, routes by subdomain)
    ↓
ForwardAuth middleware → oauth2-proxy → mPass/Cognito
    ↓
oauth2-proxy sets headers:
  X-Auth-Request-Email (user's email)
  X-Auth-Request-User (Cognito sub / unique ID)
  X-Auth-Request-Access-Token
    ↓
App receives request with headers
    ↓
App middleware reads headers → find/create user → establish session
```

## How Authentication Works

1. User visits any app (e.g., clienta-pm.moneta.com)
2. Traefik checks ForwardAuth → oauth2-proxy validates `_oauth2_proxy` session cookie
3. No cookie / expired: oauth2-proxy redirects to mPass login → user authenticates → oauth2-proxy sets cookie on `.moneta.com` → redirects back
4. Valid cookie: oauth2-proxy returns 200 with user headers → Traefik passes request + headers to app
5. App middleware reads headers, finds/creates internal user, establishes native session
6. Subsequent requests: app's native session handles auth; ForwardAuth still validates but passes through

## SSO Mechanism

- oauth2-proxy sets `_oauth2_proxy` cookie on `.moneta.com` domain
- Browser automatically sends this cookie to all `*.moneta.com` subdomains
- Each client gets their own server, so no cookie collision between clients
- Logging into one app = logged into all four apps

## Session Layers

- **Layer 1**: `_oauth2_proxy` cookie (shared across all subdomains, managed by oauth2-proxy)
- **Layer 2**: App-native session (Django session for Plane, JWT for Outline/Penpot/SurfSense)

## Key Design Decisions

- **Apps never handle OIDC/OAuth2 directly** — oauth2-proxy does all token management
- **Apps never see tokens** — they only read plain HTTP headers (X-Auth-Request-Email)
- **No passwords stored in apps** — users created with `set_unusable_password()`
- **Header trust model** — Traefik ForwardAuth overwrites any client-supplied X-Auth-Request-* headers, preventing spoofing
- **Each client has their own server** — no multi-tenancy concerns within a single deployment

## Subdomain Structure (per client)

```
clienta-pm.moneta.com      → Plane
clienta-docs.moneta.com    → Outline
clienta-design.moneta.com  → Penpot
clienta-search.moneta.com  → SurfSense
clienta-auth.moneta.com    → oauth2-proxy callback
```

## Current Focus: Plane (Django) Patch

### What We Build

A Django middleware (~50-100 lines) that:
1. Reads `X-Auth-Request-Email` and `X-Auth-Request-User` headers
2. Finds or creates a Plane user by email
3. Assigns new users to the default workspace
4. Calls `login(request, user)` to establish Django session
5. Skips if user already has a valid Django session
6. Skips bypass paths (god-mode, /api/instances)

### Files Changed in Plane

1. **New**: `plane/authentication/middleware/proxy_auth.py` — proxy auth middleware
2. **Modified**: `plane/settings/common.py` — add middleware, remove OAuth config
3. **Modified**: `plane/authentication/urls.py` — remove Google/GitHub/GitLab/Gitea OAuth endpoints
4. **Optional**: Frontend (apps/web) — remove OAuth buttons (ForwardAuth intercepts before login page loads)

### Core Middleware Logic

```python
class ProxyAuthMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.bypass_paths = getattr(settings, 'MPASS_BYPASS_PATHS', ['/god-mode', '/api/instances'])

    def __call__(self, request):
        if request.user.is_authenticated:
            return self.get_response(request)

        if any(request.path.startswith(p) for p in self.bypass_paths):
            return self.get_response(request)

        email = request.META.get('HTTP_X_AUTH_REQUEST_EMAIL')
        sub = request.META.get('HTTP_X_AUTH_REQUEST_USER')

        if not email:
            return self.get_response(request)

        from django.contrib.auth import get_user_model, login
        from django.db import IntegrityError

        User = get_user_model()
        try:
            user, created = User.objects.get_or_create(
                email=email,
                defaults={'username': sub or email}
            )
            if created:
                user.set_unusable_password()
                user.save()
                # TODO: Add to default workspace as WorkspaceMember
        except IntegrityError:
            user = User.objects.get(email=email)

        login(request, user)
        return self.get_response(request)
```

### Bypass Routes (No Auth Required)

| Path | Reason |
|------|--------|
| `/god-mode/*` | Admin panel uses local email/password |
| `/api/instances/*` | Instance admin endpoints |

### What We Remove from Plane

- Google OAuth endpoints and config
- GitHub OAuth endpoints and config
- GitLab OAuth endpoints and config
- Gitea OAuth endpoints and config
- Email/password login from user-facing routes (keep for god-mode only)

### Important: Plane has NO native OIDC support

PR #1319 attempted to add native OIDC but was never merged. Community Edition only supports Google/GitHub/GitLab/Gitea OAuth. Our approach bypasses this limitation entirely by using oauth2-proxy.

## oauth2-proxy Configuration

```yaml
OAUTH2_PROXY_PROVIDER: oidc
OAUTH2_PROXY_OIDC_ISSUER_URL: ${OIDC_BASE_URI}
OAUTH2_PROXY_CLIENT_ID: ${OIDC_CLIENT_ID}
OAUTH2_PROXY_CLIENT_SECRET: ${OIDC_CLIENT_SECRET}
OAUTH2_PROXY_COOKIE_SECRET: ${OAUTH2_PROXY_COOKIE_SECRET}
OAUTH2_PROXY_COOKIE_DOMAINS: .${PLATFORM_DOMAIN}
OAUTH2_PROXY_EMAIL_DOMAINS: "*"
OAUTH2_PROXY_SCOPE: "openid profile email"
OAUTH2_PROXY_SET_XAUTHREQUEST: "true"
OAUTH2_PROXY_PASS_ACCESS_TOKEN: "true"
OAUTH2_PROXY_COOKIE_SAMESITE: lax
OAUTH2_PROXY_REDIRECT_URL: https://${SUBDOMAIN_PREFIX}auth.${PLATFORM_DOMAIN}/oauth2/callback
```

## Traefik ForwardAuth Labels

```yaml
# Middleware definition
traefik.http.middlewares.mpass-auth.forwardauth.address: http://oauth2-proxy:4180/oauth2/auth
traefik.http.middlewares.mpass-auth.forwardauth.trustForwardHeader: true
traefik.http.middlewares.mpass-auth.forwardauth.authResponseHeaders: X-Auth-Request-Email,X-Auth-Request-User,X-Auth-Request-Access-Token

# Protected app router
traefik.http.routers.plane-secure.rule: Host(`${SUBDOMAIN_PREFIX}pm.${PLATFORM_DOMAIN}`)
traefik.http.routers.plane-secure.middlewares: mpass-auth
traefik.http.routers.plane-secure.priority: 10

# Bypass routers (higher priority, no auth)
traefik.http.routers.plane-godmode.rule: Host(`...`) && PathPrefix(`/god-mode`)
traefik.http.routers.plane-godmode.priority: 20

# OPTIONS preflight bypass (CORS)
traefik.http.routers.plane-options.rule: Host(`...`) && Method(`OPTIONS`)
traefik.http.routers.plane-options.priority: 30
```

## Cognito Details (Dev Environment)

```
Region:        us-east-1
User Pool ID:  us-east-1_TnhwOUxD0
Issuer URL:    https://cognito-idp.us-east-1.amazonaws.com/us-east-1_TnhwOUxD0
Discovery:     https://cognito-idp.us-east-1.amazonaws.com/us-east-1_TnhwOUxD0/.well-known/openid-configuration
```

## Local Development

### Testing Without Infrastructure (Fake Headers)

```python
# plane/authentication/middleware/fake_proxy_headers.py
# DEBUG ONLY — never deploy
class FakeProxyHeadersMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
    def __call__(self, request):
        if settings.DEBUG:
            request.META['HTTP_X_AUTH_REQUEST_EMAIL'] = 'testuser@example.com'
            request.META['HTTP_X_AUTH_REQUEST_USER'] = 'fake-sub-12345'
        return self.get_response(request)
```

### Testing With Real OIDC Flow (Local oauth2-proxy)

```bash
docker run -p 4180:4180 \
  -e OAUTH2_PROXY_PROVIDER=oidc \
  -e OAUTH2_PROXY_OIDC_ISSUER_URL=https://cognito-idp.us-east-1.amazonaws.com/us-east-1_TnhwOUxD0 \
  -e OAUTH2_PROXY_CLIENT_ID=your-client-id \
  -e OAUTH2_PROXY_CLIENT_SECRET=your-client-secret \
  -e OAUTH2_PROXY_COOKIE_SECRET=$(openssl rand -base64 32) \
  -e OAUTH2_PROXY_EMAIL_DOMAINS=* \
  -e OAUTH2_PROXY_SET_XAUTHREQUEST=true \
  -e OAUTH2_PROXY_UPSTREAM=http://host.docker.internal:8000 \
  -e OAUTH2_PROXY_HTTP_ADDRESS=0.0.0.0:4180 \
  -e OAUTH2_PROXY_REDIRECT_URL=http://localhost:4180/oauth2/callback \
  -e OAUTH2_PROXY_COOKIE_SECURE=false \
  -e OAUTH2_PROXY_SCOPE="openid profile email" \
  quay.io/oauth2-proxy/oauth2-proxy:v7.9.0
```

Access app via http://localhost:4180 (not :8000).

### Testing With curl

```bash
# Simulate authenticated request
curl -H "X-Auth-Request-Email: ali@example.com" \
     -H "X-Auth-Request-User: sub-123" \
     http://localhost:8000/api/some-endpoint/

# Test bypass route
curl http://localhost:8000/god-mode/

# Test no auth header
curl http://localhost:8000/api/some-endpoint/
```

## Patch Delivery

Changes delivered as git patches applied via wrapper Dockerfile:

```
patches/plane/
  001-proxy-auth-middleware.patch
  002-disable-native-auth.patch
  Dockerfile.api
  Dockerfile.web
```

```dockerfile
FROM makeplane/plane-backend:stable AS base
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*
COPY patches/plane/*.patch /tmp/patches/
RUN cd /app && git apply /tmp/patches/*.patch
RUN apt-get purge -y git && apt-get autoremove -y
```

## Security Notes

- Traefik ForwardAuth **overwrites** client-supplied X-Auth-Request-* headers — spoofing is not possible on protected routes
- Bypass routes: middleware is inactive, so spoofed headers have no effect
- All native OAuth providers removed from user-facing flows
- Only god-mode retains local email/password for admin bootstrap
- Users created with `set_unusable_password()` — cannot log in via password

## Environment Variables

### New
- `OAUTH2_PROXY_COOKIE_SECRET` — 32-byte random, base64-encoded

### Keep
- `OIDC_CLIENT_ID` — from mPass/Cognito
- `OIDC_CLIENT_SECRET` — from mPass/Cognito
- `OIDC_BASE_URI` — Cognito issuer URL

### Remove
- `OIDC_AUTH_URI` — Discovery handles this
- `OIDC_TOKEN_URI` — Discovery handles this
- `OIDC_USERINFO_URI` — Discovery handles this
- Per-app OAuth config (GOOGLE_CLIENT_ID, GITHUB_CLIENT_ID, etc.)

## Open Questions

1. Default workspace strategy for auto-provisioned Plane users
2. QR code requirement — needs clarification (may just be a URL, or may be a separate auth mechanism)
3. Should display names sync from mPass on every login or only on first creation?
4. Exact upstream Plane version to patch against

## Other Apps (Not Current Focus)

- **SurfSense (FastAPI)**: Same pattern — FastAPI dependency reads header, replaces fastapi-users
- **Outline (Koa/TypeScript)**: Middleware reads header, uses accountProvisioner, disables Passport strategies
- **Penpot (Clojure/Ring)**: Ring middleware reads header, creates profile, establishes HTTP session
