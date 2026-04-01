# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

"""
Framework-agnostic core for mPass proxy authentication.

Contains only pure Python — no Django, no FastAPI, no ORM imports.
This module is intentionally kept dependency-free so it can be extracted
into a shared package (mpass-proxy-auth) when a third Python app needs it.

Adapters (Django, FastAPI, etc.) import from here and handle all
framework-specific concerns themselves.
"""

_DEFAULT_BYPASS_PATHS = ["/god-mode", "/api/instances"]

# Fields that must be set on every newly provisioned proxy-auth user.
# Adapters should apply these to the user object after creation.
NEW_USER_FLAGS = {
    "is_password_autoset": True,
    "is_email_verified": True,
}


def normalise_email(email: str) -> str:
    """Strip whitespace and lowercase an email from a proxy header."""
    return email.strip().lower()


def is_bypass_path(path: str, bypass_paths: list) -> bool:
    """Return True if *path* starts with any of the configured bypass prefixes."""
    return any(path.startswith(p) for p in bypass_paths)


def coerce_bypass_paths(setting) -> list:
    """
    Normalise the MPASS_BYPASS_PATHS setting to a list of strings.

    Handles the three ways an env-driven setting can arrive:
    - None or falsy  → fall back to defaults
    - str            → wrap in a list (single path supplied as a string)
    - list/tuple     → convert to list
    """
    if not setting:
        return list(_DEFAULT_BYPASS_PATHS)
    if isinstance(setting, str):
        return [setting]
    return list(setting)
