from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse, urlunparse

from flask import request, url_for


_ALLOWED_REDIRECT_SCHEMES = {"http", "https"}


def current_path_with_query() -> str:
    full_path = request.full_path or request.path or "/"
    if full_path.endswith("?"):
        full_path = full_path[:-1]
    return full_path or "/"


def safe_redirect_target(target: str | None, fallback: str) -> str:
    candidate = (target or "").strip()
    if not candidate:
        return fallback

    parsed = urlparse(candidate)
    if parsed.scheme:
        if parsed.scheme not in _ALLOWED_REDIRECT_SCHEMES:
            return fallback
        if parsed.netloc != request.host:
            return fallback
        normalized = urlunparse(("", "", parsed.path or "/", parsed.params, parsed.query, parsed.fragment))
        return normalized or fallback

    if parsed.netloc:
        return fallback
    if not candidate.startswith("/"):
        return fallback
    if candidate.startswith("//"):
        return fallback
    return candidate


def login_redirect_target() -> str:
    return url_for("auth.login", next=current_path_with_query())


def path_is_within(base_dir: Path, target: Path) -> bool:
    try:
        target.resolve().relative_to(base_dir.resolve())
        return True
    except ValueError:
        return False
