import os
from datetime import datetime
from pathlib import Path

from flask import Flask, current_app, flash, redirect, request, url_for
from flask_login import LoginManager, current_user

from .datastore import DataStore


login_manager = LoginManager()
login_manager.login_view = "auth.login"


def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")

    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-key")
    data_path = Path(app.root_path).parent / "data"
    datastore = DataStore(data_path)
    app.extensions["datastore"] = datastore

    login_manager.init_app(app)

    from .auth import bp as auth_bp
    from .blog import bp as blog_bp
    from .admin import bp as admin_bp
    from .tag import bp as tag_bp
    from .messages import bp as messages_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(blog_bp)
    app.register_blueprint(admin_bp, url_prefix="/admin")
    app.register_blueprint(tag_bp, url_prefix="/tags")
    app.register_blueprint(messages_bp)

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
        if current_user.is_authenticated:
            unread_messages = datastore.count_unread_messages(current_user.username, notify_only=True)
        return {
            "is_admin": getattr(current_user, "is_admin", False),
            "current_year": datetime.now().year,
            "unread_message_count": unread_messages,
        }

    return app


@login_manager.user_loader
def load_user(user_id: str):
    datastore: DataStore = current_app.extensions.get("datastore")
    if not datastore:
        return None
    return datastore.load_user(user_id)
