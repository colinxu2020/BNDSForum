from __future__ import annotations

import logging
import threading

from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user

from .datastore import DataStore, utcnow_str


bp = Blueprint("auth", __name__, url_prefix="/auth")


def get_datastore() -> DataStore:
    return current_app.extensions["datastore"]


logger = logging.getLogger(__name__)


def _sync_class_groups_async(datastore: DataStore, username: str, password: str) -> None:
    def _runner() -> None:
        try:
            datastore.update_class_groups_from_credentials(username, password)
        except Exception:  # pragma: no cover - best effort background job
            logger.exception("异步同步班级数据失败（账号：%s）", username)

    thread = threading.Thread(target=_runner, name=f"class-sync-{username}", daemon=True)
    thread.start()


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            flash("请输入用户名和密码", "error")
        else:
            datastore = get_datastore()
            user = datastore.verify_user(username, password)
            if user is None:
                flash("用户名或密码错误", "error")
            elif getattr(user, "is_banned", False):
                flash("账号已被封禁，请联系管理员", "error")
            elif login_user(user):
                _sync_class_groups_async(datastore, username, password)
                try:
                    datastore.sync_class_tags_from_oj()
                except Exception:
                    current_app.logger.exception("登录后同步班级标签失败")
                try:
                    datastore.send_system_notification(f"用户 {username} 于 {utcnow_str()} 登录系统")
                except Exception:
                    current_app.logger.exception("发送登录系统通知失败：%s", username)
                flash("登录成功", "success")
                next_url = request.args.get("next") or url_for("blog.index")
                return redirect(next_url)
            else:
                flash("登录失败，请联系管理员", "error")
    return render_template("auth/login.html")


@bp.route("/logout")
@login_required
def logout():
    logout_user()
    flash("已退出登录", "success")
    return redirect(url_for("auth.login"))


@bp.route("/register", methods=["GET", "POST"])
def register():
    flash("注册功能现已关闭，请直接通过BNDSOJ账号登录", "error")
    return redirect(url_for("auth.login"))
    #if not current_user.is_admin:
    #    flash("只有管理员可以创建用户", "error")
    #    return redirect(url_for("blog.index"))

    datastore = get_datastore()
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        real_name = request.form.get("real_name", "").strip()
        role = "user"
        constant_tags = []

        if not username or not password or not real_name:
            flash("用户名、真实姓名和密码不能为空", "error")
        else:
            try:
                datastore.create_user(
                    username=username,
                    password=password,
                    role=role,
                    constant_tags=constant_tags,
                    real_name=real_name,
                )
            except ValueError as exc:
                flash(str(exc), "error")
            else:
                flash("注册成功，请登录", "success")
                return redirect(url_for("auth.login"))

    return render_template("auth/register.html")
