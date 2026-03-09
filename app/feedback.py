"""User feedback (用户反馈) blueprint."""
from __future__ import annotations

from flask import (
    Blueprint, current_app, flash, redirect, render_template,
    request, url_for,
)
from flask_login import current_user, login_required

from .datastore import DataStore

bp = Blueprint("feedback", __name__, url_prefix="/feedback")

FEEDBACK_CATEGORIES = [
    ("bug", "Bug 反馈"),
    ("feature", "功能建议"),
    ("general", "综合反馈"),
    ("other", "其他"),
]


def get_datastore() -> DataStore:
    return current_app.extensions["datastore"]


@bp.route("/", methods=["GET", "POST"])
@login_required
def form():
    datastore = get_datastore()

    if request.method == "POST":
        content = request.form.get("content", "").strip()
        category = request.form.get("category", "general").strip()

        if not content:
            flash("反馈内容不能为空", "error")
        elif len(content) > 5000:
            flash("反馈内容过长，最多 5000 字", "error")
        else:
            datastore.add_feedback(current_user.username, content, category)
            flash("反馈已提交，感谢您的宝贵意见！", "success")
            return redirect(url_for("feedback.form"))

    my_feedback = datastore.list_feedback(username=current_user.username)
    return render_template(
        "feedback/form.html",
        categories=FEEDBACK_CATEGORIES,
        my_feedback=my_feedback,
    )
