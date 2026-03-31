# Plane Authentication System — Codebase Analysis

> Analyzed against branch: `preview` | Date: 2026-04-01

---

## 1. User Model

**Location:** `apps/api/plane/db/models/user.py`
**Class:** `User` (extends `AbstractBaseUser`, `PermissionsMixin`)
**Table:** `users` | **Primary Key:** UUID

### Key Fields

| Field | Type | Notes |
|-------|------|-------|
| `username` | CharField(128, unique) | Set to UUID hex for OAuth users |
| `email` | CharField(255, unique) | Primary login identifier; lowercased in `save()` |
| `display_name` | CharField(255) | Auto-generated from email prefix in `save()` (lines 177-182) |
| `first_name`, `last_name` | CharField(255) | Populated from OAuth provider |
| `is_password_autoset` | BooleanField(default=False) | True for all OAuth users |
| `is_email_verified` | BooleanField(default=False) | Set True for OAuth users (no email confirmation) |
| `is_active` | BooleanField(default=True) | |
| `is_bot` | BooleanField(default=False) | |
| `avatar` | TextField | Fallback URL if S3 upload fails |
| `avatar_asset` | ForeignKey(FileAsset) | S3-uploaded avatar |
| `last_login_medium` | CharField(default="email") | Set to provider name ("github", etc.) |
| `last_active`, `last_login_time` | DateTimeField | Updated on every login |
| `last_login_ip`, `last_login_uagent` | CharField | Tracking fields |
| `token_updated_at` | DateTimeField | |

**Auth config:**
- `USERNAME_FIELD = "email"` (line 128)
- `REQUIRED_FIELDS = ["username"]` (line 129)
- `objects = UserManager()` (line 131) — Django default manager

**Post-save signal** (line 298): creates `UserNotificationPreference` on new user creation.

---

## 2. Workspace & WorkspaceMember Models

**Location:** `apps/api/plane/db/models/workspace.py`

### Workspace

**Table:** `workspaces`

| Field | Notes |
|-------|-------|
| `name` | CharField(80) |
| `slug` | SlugField(unique) — URL identifier |
| `owner` | ForeignKey(User) |
| `logo`, `logo_asset` | Workspace branding |
| `timezone` | default="UTC" |

### WorkspaceMember

**Table:** `workspace_members`
**Unique constraint:** `(workspace, member)` when `deleted_at IS NULL`

| Field | Notes |
|-------|-------|
| `workspace` | ForeignKey(Workspace) |
| `member` | ForeignKey(User) |
| `role` | PositiveSmallIntegerField — `20=Admin, 15=Member, 5=Guest` (default=5) |
| `is_active` | BooleanField(default=True) |
| `view_props`, `default_props`, `issue_props` | JSONField — user prefs |

### Programmatic Member Creation

**Single member** (invitation acceptance):
```python
# plane/authentication/utils/workspace_project_join.py, lines 26-36
WorkspaceMember.objects.create(
    workspace_id=workspace_member_invite.workspace_id,
    member=user,
    role=workspace_member_invite.role,
)
```

**Bulk creation** (OAuth signup with pending invites):
```python
WorkspaceMember.objects.bulk_create(
    [...],
    ignore_conflicts=True,  # handles soft-deleted records
)
```

**No auto-assignment to a default workspace on signup** — users only get workspace membership via accepted invitations.

---

## 3. MIDDLEWARE Order

**Location:** `apps/api/plane/settings/common.py`, lines 62-77

```python
MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",                              # line 64
    "django.middleware.security.SecurityMiddleware",                      # line 65
    "whitenoise.middleware.WhiteNoiseMiddleware",                         # line 66
    "plane.authentication.middleware.session.SessionMiddleware",          # line 67 — CUSTOM
    "django.middleware.common.CommonMiddleware",                          # line 68
    "django.middleware.csrf.CsrfViewMiddleware",                          # line 69
    "django.contrib.auth.middleware.AuthenticationMiddleware",            # line 70
    "django.middleware.clickjacking.XFrameOptionsMiddleware",             # line 71
    "crum.CurrentRequestUserMiddleware",                                  # line 72
    "django.middleware.gzip.GZipMiddleware",                              # line 73
    "plane.middleware.request_body_size.RequestBodySizeLimitMiddleware",  # line 74
    "plane.middleware.logger.APITokenLogMiddleware",                      # line 75
    "plane.middleware.logger.RequestLoggerMiddleware",                    # line 76
]
```

**Our `ProxyAuthMiddleware` must go after `AuthenticationMiddleware` (line 70)** so that `request.user` is populated before we check `request.user.is_authenticated`.

### Custom SessionMiddleware

**File:** `apps/api/plane/authentication/middleware/session.py`

- `process_request()`: loads session from `ADMIN_SESSION_COOKIE_NAME` (for `/instances` paths) or `SESSION_COOKIE_NAME`
- `process_response()`: saves session with appropriate cookie, handles expiry, deletion, refresh

---

## 4. OAuth URL Endpoints

**Location:** `apps/api/plane/authentication/urls.py`

| Provider | Initiate | Callback |
|----------|----------|----------|
| Google | `/auth/google/` | `/auth/google/callback/` |
| GitHub | `/auth/github/` | `/auth/github/callback/` |
| GitLab | `/auth/gitlab/` | `/auth/gitlab/callback/` |
| Gitea | `/auth/gitea/` | `/auth/gitea/callback/` |

Each provider also has `/auth/spaces/{provider}/` and `/auth/spaces/{provider}/callback/` variants.

**Other endpoints:**
- Magic link: `magic-generate/`, `magic-sign-in/`, `magic-sign-up/`
- Email/password: `sign-in/`, `sign-up/`, `email-check/`
- Password management: `forgot-password/`, `reset-password/`, `change-password/`, `set-password/`
- CSRF: `get-csrf-token/`

---

## 5. How OAuth Creates Users (GitHub Example)

### Flow

```
GitHubOauthInitiateEndpoint.get()
  -> store host/next_path in session
  -> generate state UUID -> store in session
  -> redirect to github.com/login/oauth/authorize

GitHubCallbackEndpoint.get()
  -> validate state (CSRF)
  -> validate code present
  -> GitHubOAuthProvider(code, request, callback=post_user_auth_workflow)
  -> provider.authenticate()
       -> set_token_data()           # POST to github.com/login/oauth/access_token
       -> set_user_data()            # GET /user, GET /user/emails, GET /orgs/{org}
       -> complete_login_or_signup() [base.py]
  -> user_login(request, user)       # Django login() + session save
  -> HttpResponseRedirect(next_path or default)
```

### User Creation (`complete_login_or_signup`, `apps/api/plane/authentication/adapter/base.py`)

```python
# line 296-299: check existence
user = User.objects.filter(email=email).first()
is_signup = not bool(user)

# line 301-342: create new user
if not user:
    user = User(email=email, username=uuid.uuid4().hex)   # line 306
    user.set_password(uuid.uuid4().hex)                   # line 310 — random, unusable
    user.is_password_autoset = True                       # line 311
    user.is_email_verified = True                         # line 312
    user.first_name = ...
    user.last_name = ...
    user.save()                                           # line 328
    # download avatar from provider URL -> upload to S3 -> create FileAsset
    Profile.objects.create(user=user)                     # line 342

# lines 348-349: update login tracking fields
user.last_login_medium = self.provider  # "github"
user.last_active = timezone.now()
...
user.save()

# line 353: run invitation callback
if self.callback:
    self.callback(user, is_signup, self.request)  # post_user_auth_workflow

# line 357: create/update Account (OAuth token storage)
self.create_update_account(user=user)
```

### Fields Set on New OAuth User

| Field | Value |
|-------|-------|
| `username` | `uuid4().hex` |
| `email` | provider email (lowercased) |
| `password` | `uuid4().hex` (hashed, never exposed) |
| `is_password_autoset` | `True` |
| `is_email_verified` | `True` |
| `first_name` | from provider |
| `last_name` | from provider |
| `display_name` | auto from email prefix (in `save()`) |
| `avatar_asset` | FileAsset (S3 upload) |
| `avatar` | provider URL (fallback) |
| `is_active` | `True` |
| `last_login_medium` | `"github"` |

### Invitation Processing (`post_user_auth_workflow`)

**File:** `apps/api/plane/authentication/utils/workspace_project_join.py`

1. Fetch `WorkspaceMemberInvite.objects.filter(email=user.email, accepted=True)`
2. `WorkspaceMember.objects.bulk_create([...], ignore_conflicts=True)`
3. Invalidate cache, track analytics
4. Same pattern for `ProjectMemberInvite`
5. Delete processed invites

**Critical:** new users only land in workspaces if they have accepted invitations. There is no "default workspace" auto-join.

### Session Login (`user_login`)

**File:** `apps/api/plane/authentication/utils/login.py`

```python
def user_login(request, user, is_app=False, is_admin=False, is_space=False):
    login(request=request, user=user)          # Django auth.login()
    if is_admin:
        request.session.set_expiry(settings.ADMIN_SESSION_COOKIE_AGE)
    request.session["device_info"] = {
        "user_agent": ...,
        "ip_address": ...,
        "domain": ...,
    }
    request.session.save()
```

---

## 6. Implications for ProxyAuthMiddleware

### Placement in MIDDLEWARE list

Insert **after** `AuthenticationMiddleware` (line 70) and **before** logger middlewares:

```python
"django.contrib.auth.middleware.AuthenticationMiddleware",                # line 70
"plane.authentication.middleware.proxy_auth.ProxyAuthMiddleware",         # NEW
"django.middleware.clickjacking.XFrameOptionsMiddleware",                 # line 71
```

### User creation

Match existing OAuth pattern:
```python
import uuid
from plane.db.models import Profile

user = User(email=email, username=uuid.uuid4().hex)
user.set_unusable_password()   # more explicit than random UUID
user.is_password_autoset = True
user.is_email_verified = True
user.save()
Profile.objects.create(user=user)
```

### Workspace membership

No default workspace exists in existing OAuth flow. Strategy options:
1. **No assignment** — user sees empty state, must be invited (matches existing OAuth behavior)
2. **Configured default** — `MPASS_DEFAULT_WORKSPACE_SLUG` env var, assign as Guest
3. **First workspace** — fragile

Recommendation: Option 1 (match OAuth behavior) unless product requires otherwise. See Open Questions in CLAUDE.md.

### Session establishment

Call `user_login(request, user, is_app=True)` (existing utility at `apps/api/plane/authentication/utils/login.py`) — not raw `login()` — so device_info is stored and correct session cookie is selected.

### Backend for `login()`

Call `login()` with explicit backend to avoid ambiguity:
```python
login(request, user, backend="django.contrib.auth.backends.ModelBackend")
```

---

## 7. Files to Create / Modify

| File | Action | Notes |
|------|--------|-------|
| `apps/api/plane/authentication/middleware/proxy_auth.py` | **Create** | Core middleware |
| `apps/api/plane/settings/common.py` | **Modify** | Add to MIDDLEWARE list after AuthenticationMiddleware |
| `apps/api/plane/authentication/urls.py` | **Modify** | Remove OAuth provider endpoints |

### Optional (frontend)
- `apps/web/` — Remove OAuth provider buttons (ForwardAuth intercepts before the login page loads anyway)
