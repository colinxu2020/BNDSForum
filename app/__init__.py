import os
from datetime import datetime
from pathlib import Path

from flask import Flask, current_app
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

    app.register_blueprint(auth_bp)
    app.register_blueprint(blog_bp)
    app.register_blueprint(admin_bp, url_prefix="/admin")
    app.register_blueprint(tag_bp, url_prefix="/tags")

    @app.context_processor
    def inject_globals():
        return {
            "is_admin": getattr(current_user, "is_admin", False),
            "current_year": datetime.now().year,
        }

    return app


@login_manager.user_loader
def load_user(user_id: str):
    datastore: DataStore = current_app.extensions.get("datastore")
    if not datastore:
        return None
    return datastore.load_user(user_id)
