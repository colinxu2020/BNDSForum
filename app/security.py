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
    from werkzeug.urls import url_parse
    target = (target or "").strip()
    if not target:
        return fallback

    # Reconstruct the URL without netloc to guarantee an intra-site redirect
    parsed = urlparse(target)
    if parsed.netloc:
        if parsed.netloc.lower() != request.host.lower():
            return fallback

    # Reconstructing guarantees we lose any tricky authority prefix
    safe_path = parsed.path or "/"
    if parsed.query:
        safe_path += f"?{parsed.query}"
    
    # Avoid protocol-relative URLs that might trick browsers
    if safe_path.startswith("//"):
        safe_path = "/" + safe_path.lstrip("/")
        
    return safe_path


def login_redirect_target() -> str:
    return url_for("auth.login", next=current_path_with_query())

