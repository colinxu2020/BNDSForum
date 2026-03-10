import os
import secrets
import hmac
from datetime import datetime
from pathlib import Path

from flask import Flask, abort, current_app, flash, redirect, request, session, url_for
from flask_login import LoginManager, current_user

from .datastore import DataStore
from .security import login_redirect_target


login_manager = LoginManager()
login_manager.login_view = "auth.login"


def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")

    secret_key = os.getenv("SECRET_KEY", "")
    if not secret_key:
        import secrets as _secrets
        secret_key = _secrets.token_hex(32)
        import logging as _logging
        _logging.getLogger(__name__).warning(
            "SECRET_KEY 未设置，本次使用随机密钥（所有 session 将在重启后失效）。"
            "请在生产部署中通过环境变量 SECRET_KEY 配置持久密钥。"
        )
    app.config["SECRET_KEY"] = secret_key
    # Session cookie hardening
    app.config.setdefault("SESSION_COOKIE_HTTPONLY", True)
    app.config.setdefault("SESSION_COOKIE_SAMESITE", "Lax")
    # HTTPS 环境下建议额外设置 SESSION_COOKIE_SECURE=True（通过环境变量启用）
    if os.getenv("SESSION_COOKIE_SECURE", "").lower() in {"1", "true", "yes"}:
        app.config["SESSION_COOKIE_SECURE"] = True
    data_path = Path(app.root_path).parent / "data"
    datastore = DataStore(data_path)
    app.extensions["datastore"] = datastore

    login_manager.init_app(app)

    from .auth import bp as auth_bp
    from .blog import bp as blog_bp
    from .admin import bp as admin_bp
    from .messages import bp as messages_bp
    from .tag import bp as tag_bp
    from .uploads import bp as uploads_bp
    from .drive import bp as drive_bp
    from .feedback import bp as feedback_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(blog_bp)
    app.register_blueprint(admin_bp, url_prefix="/admin")
    app.register_blueprint(messages_bp)
    app.register_blueprint(tag_bp)
    app.register_blueprint(uploads_bp)
    app.register_blueprint(drive_bp)
    app.register_blueprint(feedback_bp)

    def _get_csrf_token() -> str:
        token = session.get("_csrf_token")
        if not token:
            token = secrets.token_hex(16)
            session["_csrf_token"] = token
        return token

    @app.before_request
    def csrf_protect():
        if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
            return None
        token = session.get("_csrf_token")
        submitted = request.form.get("_csrf_token") or request.headers.get("X-CSRFToken")
        if not token or not submitted or not hmac.compare_digest(submitted, token):
            abort(400)

    @app.before_request
    def enforce_login_guard():
        if current_user.is_authenticated:
            return None
        endpoint = request.endpoint or ""
        if endpoint in {"auth.login", "drive.share_page", "drive.share_download", "drive.share_qr"} or endpoint.startswith("static"):
            return None
        return redirect(login_redirect_target())

    @app.before_request
    def enforce_banned_guard():
        if not current_user.is_authenticated:
            return None
        if not getattr(current_user, "is_banned", False):
            return None
        endpoint = request.endpoint or ""
        if endpoint == "auth.logout" or endpoint.startswith("static"):
            return None
        flash("账号已被封禁，请联系管理员", "error")
        return redirect(url_for("auth.logout"))

    @app.context_processor
    def inject_globals():
        unread_messages = 0
        theme_preference = None
        if current_user.is_authenticated:
            unread_messages = datastore.count_unread_messages(current_user.username, notify_only=True)
            theme_preference = datastore.get_user_theme(current_user.username)
        return {
            "is_admin": getattr(current_user, "is_admin", False),
            "current_year": datetime.now().year,
            "unread_message_count": unread_messages,
            "csrf_token": _get_csrf_token,
            "theme_preference": theme_preference,
        }

    return app


@login_manager.user_loader
def load_user(user_id: str):
    datastore: DataStore = current_app.extensions.get("datastore")
    if not datastore:
        return None
    return datastore.load_user(user_id)
