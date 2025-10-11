from __future__ import annotations

from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user

from .datastore import DataStore


bp = Blueprint("auth", __name__, url_prefix="/auth")


def get_datastore() -> DataStore:
    return current_app.extensions["datastore"]


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
            if user:
                login_user(user)
                flash("登录成功", "success")
                next_url = request.args.get("next") or url_for("blog.index")
                return redirect(next_url)
            flash("用户名或密码错误", "error")
    return render_template("auth/login.html")


@bp.route("/logout")
@login_required
def logout():
    logout_user()
    flash("已退出登录", "success")
    return redirect(url_for("auth.login"))


@bp.route("/register", methods=["GET", "POST"])
def register():
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
