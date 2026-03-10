from __future__ import annotations

import logging
import threading

from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user

from .datastore import DataStore, utcnow_str
from .security import safe_redirect_target


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


def _sync_class_groups_async_cookie(datastore: DataStore, username: str, phpsessid: str) -> None:
    def _runner() -> None:
        try:
            datastore.update_class_groups_from_cookie(username, phpsessid)
        except Exception:  # pragma: no cover - best effort background job
            logger.exception("异步同步班级数据失败（Cookie 登录，账号：%s）", username)

    thread = threading.Thread(target=_runner, name=f"class-sync-cookie-{username}", daemon=True)
    thread.start()


@bp.route("/login", methods=["GET", "POST"])
def login():
    phpsessid_cookie = request.cookies.get("PHPSESSID", "").strip()
    datastore = get_datastore()

    def _resolve_username_from_cookie(phpsessid: str) -> str | None:
        if not phpsessid:
            return None
        try:
            return datastore.resolve_username_from_cookie(phpsessid)
        except Exception:
            logger.exception("解析 Cookie 中用户名失败")
            return None

    resolved_username = _resolve_username_from_cookie(phpsessid_cookie)

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        phpsessid_form = (request.form.get("phpsessid") or "").strip()
        use_cookie_login = bool(request.form.get("use_cookie_login"))
        phpsessid = phpsessid_form or phpsessid_cookie

        if not username and phpsessid:
            username = resolved_username or _resolve_username_from_cookie(phpsessid)
            if not username:
                flash("未能从 Cookie 读取用户名，请确认已登录 BNDSOJ", "error")

        if not username or (not password and not phpsessid):
            flash("请输入用户名，并提供密码或 PHPSESSID Cookie", "error")
        else:
            datastore = get_datastore()
            user = None
            used_cookie = False
            if phpsessid and (use_cookie_login or not password):
                user = datastore.verify_user_with_cookie(username, phpsessid)
                used_cookie = user is not None
                if user is None and not password:
                    flash("Cookie 登录失败，请检查 PHPSESSID 是否过期", "error")
            if user is None and password:
                user = datastore.verify_user(username, password)
            if user is None:
                if not phpsessid:
                    flash("用户名或密码错误", "error")
                else:
                    flash("登录失败：Cookie 无效或已过期", "error")
            elif getattr(user, "is_banned", False):
                flash("账号已被封禁，请联系管理员", "error")
            elif login_user(user):
                try:
                    if used_cookie:
                        _sync_class_groups_async_cookie(datastore, username, phpsessid)
                    elif password:
                        _sync_class_groups_async(datastore, username, password)
                except Exception:
                    logger.exception("登录后班级同步启动失败（账号：%s）", username)
                try:
                    datastore.send_system_notification(f"用户 {username} 于 {utcnow_str()} 登录系统")
                except Exception:
                    current_app.logger.exception("发送登录系统通知失败：%s", username)
                flash("登录成功", "success")
                next_url = (request.args.get("next") or "").strip()
                from urllib.parse import urlparse
                if not next_url or urlparse(next_url).netloc != "" or not next_url.startswith("/") or next_url.startswith("//"):
                    next_url = url_for("blog.index")
                return redirect(next_url)
            else:
                flash("登录失败，请联系管理员", "error")
        resolved_username = username or resolved_username
    return render_template(
        "auth/login.html",
        has_phpsessid_cookie=bool(phpsessid_cookie),
        resolved_username=resolved_username,
    )


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
