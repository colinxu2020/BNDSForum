from __future__ import annotations

import markdown2
from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from markupsafe import Markup

from .datastore import DataStore


bp = Blueprint("blog", __name__)

_MARKDOWN_EXTRAS = [
    "fenced-code-blocks",
    "tables",
    "strike",
    "task_list",
    "cuddled-lists",
    "metadata",
]
_markdowner = markdown2.Markdown(extras=_MARKDOWN_EXTRAS, safe_mode="escape")


@bp.app_template_filter("markdown")
def render_markdown(value: str | None) -> Markup:
    if not value:
        return Markup("")
    _markdowner.reset()
    html = _markdowner.convert(value)
    return Markup(html)


def get_datastore() -> DataStore:
    return current_app.extensions["datastore"]


def _user_lookup(datastore: DataStore) -> dict[str, dict[str, object]]:
    users = datastore.list_users()
    return {user["username"]: user for user in users}


def _decorate_post(post: dict, user_map: dict[str, dict[str, object]]) -> dict:
    record = user_map.get(post.get("author"), {})
    decorated = {**post}
    decorated["author_username"] = post.get("author")
    decorated["author_real_name"] = record.get("real_name", "") if record else ""
    decorated["author_display"] = decorated["author_real_name"] or decorated["author_username"]
    decorated["author_constant_tags"] = record.get("constant_tags", []) if record else []
    return decorated


def _decorate_comment(comment: dict, user_map: dict[str, dict[str, object]]) -> dict:
    record = user_map.get(comment.get("author"), {})
    decorated = {**comment}
    decorated["author_real_name"] = record.get("real_name", "") if record else ""
    decorated["author_display"] = decorated["author_real_name"] or decorated.get("author")
    return decorated


@bp.route("/")
def index():
    datastore = get_datastore()
    user_map = _user_lookup(datastore)
    posts = [_decorate_post(post, user_map) for post in datastore.list_posts()]
    normal_tags = datastore.list_normal_tags()
    return render_template(
        "blog/index.html",
        posts=posts,
        normal_tags=normal_tags,
    )


@bp.route("/post/new", methods=["GET", "POST"])
@login_required
def create():
    datastore = get_datastore()
    available_tags = datastore.list_normal_tags()
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        content = request.form.get("content", "").strip()
        selected_tags = request.form.getlist("normal_tags")
        tags = set(selected_tags) | set(getattr(current_user, "constant_tags", []))
        if not title or not content:
            return render_template(
                "blog/edit.html",
                available_tags=available_tags,
                selected_tags=selected_tags,
                title=title,
                content=content,
                error="标题和内容不能为空",
                post_id=None,
            )
        datastore.create_post(
            author=current_user.username,
            title=title,
            content=content,
            tags=tags,
        )
        flash("文章创建成功", "success")
        return redirect(url_for("blog.index"))
    return render_template(
        "blog/edit.html",
        available_tags=available_tags,
        selected_tags=[],
        title="",
        content="",
        post_id=None,
        error=None,
    )


def _can_edit(post: dict) -> bool:
    if not current_user.is_authenticated:
        return False
    if current_user.is_admin:
        return True
    return post.get("author") == current_user.username


@bp.route("/post/<post_id>", methods=["GET", "POST"])
def detail(post_id: str):
    datastore = get_datastore()
    post = datastore.get_post(post_id)
    if not post:
        abort(404)
    if request.method == "POST":
        if not current_user.is_authenticated:
            flash("请先登录后再发表评论", "error")
            return redirect(url_for("auth.login", next=request.url))
        content = request.form.get("content", "").strip()
        if not content:
            flash("评论内容不能为空", "error")
        else:
            datastore.add_comment(post_id, current_user.username, content)
            flash("评论已发布", "success")
            return redirect(url_for("blog.detail", post_id=post_id))
    user_map = _user_lookup(datastore)
    decorated_post = _decorate_post(post, user_map)
    comments = [_decorate_comment(comment, user_map) for comment in post.get("comments", [])]
    return render_template(
        "blog/detail.html",
        post=decorated_post,
        comments=comments,
        can_edit=_can_edit(post),
    )


@bp.route("/post/<post_id>/edit", methods=["GET", "POST"])
@login_required
def edit(post_id: str):
    datastore = get_datastore()
    post = datastore.get_post(post_id)
    if not post:
        abort(404)
    if not _can_edit(post):
        flash("没有权限编辑该文章", "error")
        return redirect(url_for("blog.detail", post_id=post_id))

    available_tags = datastore.list_normal_tags()
    author_record = datastore.get_user(post["author"]) or {}
    author_constant_tags = set(author_record.get("constant_tags", []))
    existing_tags = set(post.get("tags", []))
    extra_tags = existing_tags - author_constant_tags - set(available_tags)

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        content = request.form.get("content", "").strip()
        selected_tags = set(request.form.getlist("normal_tags"))
        if not title or not content:
            flash("标题和内容不能为空", "error")
        else:
            final_tags = author_constant_tags | selected_tags | extra_tags
            datastore.update_post(
                post_id,
                title=title,
                content=content,
                tags=final_tags,
            )
            flash("文章已更新", "success")
            return redirect(url_for("blog.detail", post_id=post_id))
    selected_tags = [tag for tag in post.get("tags", []) if tag in available_tags]
    return render_template(
        "blog/edit.html",
        available_tags=available_tags,
        selected_tags=selected_tags,
        title=post.get("title", ""),
        content=post.get("content", ""),
        post_id=post_id,
        error=None,
        author_constant_tags=list(author_constant_tags),
        extra_tags=list(extra_tags),
    )


@bp.route("/post/<post_id>/delete", methods=["POST"])
@login_required
def delete(post_id: str):
    datastore = get_datastore()
    post = datastore.get_post(post_id)
    if not post:
        abort(404)
    if not _can_edit(post):
        flash("没有权限删除该文章", "error")
        return redirect(url_for("blog.detail", post_id=post_id))
    datastore.delete_post(post_id)
    flash("文章已删除", "success")
    return redirect(url_for("blog.index"))


@bp.route("/user/<username>", methods=["GET", "POST"])
def user_profile(username: str):
    datastore = get_datastore()
    user_record = datastore.get_user(username)
    if not user_record:
        abort(404)

    can_edit_real_name = current_user.is_authenticated and (
        current_user.is_admin or current_user.username == username
    )

    if request.method == "POST":
        if not can_edit_real_name:
            abort(403)
        real_name = request.form.get("real_name", "").strip()
        if not real_name:
            flash("真实姓名不能为空", "error")
        else:
            datastore.update_user_real_name(username, real_name)
            flash("真实姓名已更新", "success")
            return redirect(url_for("blog.user_profile", username=username))

    user_map = _user_lookup(datastore)
    user_posts = [
        _decorate_post(post, user_map) for post in datastore.list_posts() if post.get("author") == username
    ]
    return render_template(
        "blog/user_profile.html",
        profile=user_record,
        posts=user_posts,
        can_edit_real_name=can_edit_real_name,
    )
