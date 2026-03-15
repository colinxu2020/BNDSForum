from __future__ import annotations

from flask import request, url_for

_ALLOWED_REDIRECT_SCHEMES = {"http", "https"}


def current_path_with_query() -> str:
    full_path = request.full_path or request.path or "/"
    if full_path.endswith("?"):
        full_path = full_path[:-1]
    return full_path or "/"


def safe_redirect_target(target: str | None, fallback: str) -> str:
    target = (target or "").strip()
    if not target:
        return fallback

    # A widely recognized reliable check for open redirects
    # Must explicitly start with a single slash, and not double slash
    if target.startswith("/") and not target.startswith("//"):
        return target

    return fallback


def login_redirect_target() -> str:
    return url_for("auth.login", next=current_path_with_query())

