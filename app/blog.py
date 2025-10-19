
from __future__ import annotations

import re
from typing import Dict, List, Optional, Set, Tuple

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from markupsafe import Markup
from markdown_it import MarkdownIt
from markdown_it.token import Token
from mdit_py_plugins.container import container_plugin
from mdit_py_plugins.tasklists import tasklists_plugin

from .datastore import DataStore


bp = Blueprint("blog", __name__)

_MATH_SEGMENT_RE = re.compile(
    r"(\\\[[\s\S]*?\\\]|\\\([\s\S]*?\\\)|\$\$[\s\S]*?\$\$|\$(?!\$)[^$]*?\$)"
)
_KATEX_BRACE_PLACEHOLDERS = {
    r"\{": "KATEXLEFTBRACEPLACEHOLDER",
    r"\}": "KATEXRIGHTBRACEPLACEHOLDER",
}

_CALLOUT_KINDS = {"info", "success", "warning", "error"}
_CALLOUT_DEFAULT_TITLES = {
    "info": "Info",
    "success": "Success",
    "warning": "Warning",
    "error": "Error",
}
_CALLOUT_INFO_RE = re.compile(r"^([\w-]+)(?:\[([^\]]*)\])?(?:\{([^}]*)\})?")

_MENTION_RE = re.compile(r"@([A-Za-z0-9_]{1,32})")


def _parse_callout_info(params: str) -> Tuple[str, str | None, Dict[str, str]] | None:
    stripped = params.strip()
    match = _CALLOUT_INFO_RE.match(stripped)
    if not match:
        return None
    kind, label, attr_string = match.groups()
    if kind not in _CALLOUT_KINDS:
        return None
    attributes: Dict[str, str] = {}
    if attr_string:
        for raw in re.split(r"\s+", attr_string.strip()):
            if not raw:
                continue
            if "=" in raw:
                key, value = raw.split("=", 1)
                value = value.strip('"\'')
            else:
                key, value = raw, "true"
            attributes[key] = value
    return kind, label, attributes


def _truthy(value: str | None) -> bool:
    if value is None:
        return False
    return value.strip().lower() not in {"", "0", "false", "none", "no", "off"}


def _render_inline(md: MarkdownIt, text: str) -> str:
    if not text:
        return ""
    protected = _protect_katex_braces(text)
    rendered = md.renderInline(protected)
    return _restore_katex_braces(rendered)


def _register_callout_plugin(md: MarkdownIt) -> None:
    def validate(params: str, markup: str) -> bool:
        return _parse_callout_info(params) is not None

    def render(self, tokens: list[Token], idx: int, options, env) -> str:
        token = tokens[idx]
        parsed = _parse_callout_info(token.info or "") or ("info", None, {})
        kind, label, attrs = parsed
        label_text = label or _CALLOUT_DEFAULT_TITLES[kind]
        summary_html = _render_inline(md, label_text)
        class_attr = f' class="callout callout-{kind}"'
        open_attr = " open" if _truthy(attrs.get("open")) else ""
        if token.nesting == 1:
            return (
                f"<details{class_attr}{open_attr}>"
                f"<summary><span class=\"callout-title\">{summary_html}</span></summary>"
                "<div class=\"callout-content\">"
            )
        return "</div></details>"

    for kind in _CALLOUT_KINDS:
        container_plugin(md, kind, validate=validate, render=render)


def _create_markdown_renderer() -> MarkdownIt:
    md = MarkdownIt("commonmark", {"html": False, "linkify": True})
    md.enable("strikethrough")
    md.enable("table")
    md.use(tasklists_plugin)
    _register_callout_plugin(md)
    return md


_markdowner = _create_markdown_renderer()


def _protect_katex_braces(source: str) -> str:
    def _replace(match: re.Match[str]) -> str:
        segment = match.group(0)
        for token, placeholder in _KATEX_BRACE_PLACEHOLDERS.items():
            segment = segment.replace(token, placeholder)
        return segment

    return _MATH_SEGMENT_RE.sub(_replace, source)


def _restore_katex_braces(rendered: str) -> str:
    for token, placeholder in _KATEX_BRACE_PLACEHOLDERS.items():
        rendered = rendered.replace("\\" + placeholder, placeholder)
        rendered = rendered.replace(placeholder, token)
    return rendered


@bp.app_template_filter("markdown")
def render_markdown(value: str | None) -> Markup:
    if not value:
        return Markup("")
    protected = _protect_katex_braces(value)
    html = _markdowner.render(protected)
    html = _restore_katex_braces(html)
    return Markup(html)


def _extract_mentions(content: str) -> Set[str]:
    if not content:
        return set()
    return {match.group(1) for match in _MENTION_RE.finditer(content)}


def _notify_mentions(
    datastore: DataStore,
    author_username: str,
    author_display: str,
    post_id: str,
    post: dict,
    comment: Dict[str, Any],
    raw_content: str,
) -> None:
    mentions = _extract_mentions(raw_content)
    if not mentions:
        return
    post_title = str(post.get("title") or "未命名文章")
    permalink = url_for("blog.detail", post_id=post_id, _external=True) + f"#comment-{comment['id']}"
    snippet = raw_content.strip()
    if len(snippet) > 120:
        snippet = snippet[:117] + "..."
    message_template = (
        "{author} 在《{title}》的评论中 @ 了你：\n"
        "{snippet}\n"
        "查看评论：{link}"
    )
    for username in mentions:
        if username == author_username:
            continue
        if not datastore.get_user(username):
            continue
        try:
            datastore.send_private_message(
                author_username,
                username,
                message_template.format(
                    author=author_display,
                    title=post_title,
                    snippet=snippet or "(评论内容为空)",
                    link=permalink,
                ),
            )
        except (PermissionError, ValueError):
            continue


def get_datastore() -> DataStore:
    return current_app.extensions["datastore"]


def _notify_system(message: str) -> None:
    datastore = get_datastore()
    try:
        datastore.send_system_notification(message)
    except Exception:  # pragma: no cover
        current_app.logger.exception("发送系统通知失败：%s", message)


def _user_lookup(datastore: DataStore) -> dict[str, dict[str, object]]:
    users = datastore.list_users()
    return {user["username"]: user for user in users}


def _decorate_post(
    post: dict,
    user_map: dict[str, dict[str, object]],
    favorite_post_ids: Optional[Set[str]] = None,
) -> dict:
    record = user_map.get(post.get("author"), {})
    decorated = {**post}
    decorated["author_username"] = post.get("author")
    decorated["author_real_name"] = record.get("real_name", "") if record else ""
    decorated["author_display"] = decorated["author_real_name"] or decorated["author_username"]
    decorated["author_constant_tags"] = record.get("constant_tags", []) if record else []
    decorated["favorite_count"] = post.get("favorite_count", 0)
    if favorite_post_ids is not None:
        decorated["is_favorited"] = post.get("id") in favorite_post_ids
    else:
        decorated["is_favorited"] = False
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
    raw_posts = datastore.list_posts()
    favorite_post_ids: Set[str] = set()
    if current_user.is_authenticated:
        favorite_post_ids = datastore.favorite_post_ids(
            current_user.username,
            [post["id"] for post in raw_posts],
        )
    posts = [_decorate_post(post, user_map, favorite_post_ids) for post in raw_posts]
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
        title_display = title if len(title) <= 40 else title[:37] + "…"
        _notify_system(f"用户 {current_user.username} 发布文章《{title_display}》")
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
            comment_record = datastore.add_comment(post_id, current_user.username, content)
            author_display = getattr(current_user, "real_name", "") or current_user.username
            _notify_mentions(datastore, current_user.username, author_display, post_id, post, comment_record, content)
            flash("评论已发布", "success")
            snippet = content if len(content) <= 60 else content[:57] + "…"
            title_display = post.get("title", "")
            title_display = title_display if len(title_display) <= 40 else title_display[:37] + "…"
            _notify_system(f"用户 {current_user.username} 在文章《{title_display}》发表评论：{snippet}")
            return redirect(url_for("blog.detail", post_id=post_id))
    user_map = _user_lookup(datastore)
    favorite_post_ids: Set[str] = set()
    if current_user.is_authenticated:
        favorite_post_ids = datastore.favorite_post_ids(current_user.username, [post_id])
    decorated_post = _decorate_post(post, user_map, favorite_post_ids)
    comments = [_decorate_comment(comment, user_map) for comment in post.get("comments", [])]
    return render_template(
        "blog/detail.html",
        post=decorated_post,
        comments=comments,
        can_edit=_can_edit(post),
    )


@bp.route("/post/<post_id>/favorite", methods=["POST"])
@login_required
def favorite(post_id: str):
    datastore = get_datastore()
    post = datastore.get_post(post_id)
    if not post:
        flash("未找到文章，无法进行收藏操作", "error")
        return redirect(url_for("blog.index"))
    title_display = post.get("title", "")
    title_display = title_display if len(title_display) <= 40 else title_display[:37] + "…"
    action = (request.form.get("action") or "add").strip().lower()
    next_url = request.form.get("next") or request.referrer or url_for("blog.detail", post_id=post_id)
    try:
        if action == "remove":
            removed = datastore.unfavorite_post(post_id, current_user.username)
            flash("已取消收藏" if removed else "该文章不在收藏夹中", "success" if removed else "info")
            if removed:
                _notify_system(f"用户 {current_user.username} 取消收藏文章《{title_display}》")
        elif action == "toggle":
            if datastore.is_post_favorited(post_id, current_user.username):
                datastore.unfavorite_post(post_id, current_user.username)
                flash("已取消收藏", "success")
                _notify_system(f"用户 {current_user.username} 取消收藏文章《{title_display}》")
            else:
                datastore.favorite_post(post_id, current_user.username)
                flash("收藏成功", "success")
                _notify_system(f"用户 {current_user.username} 收藏文章《{title_display}》")
        else:
            added = datastore.favorite_post(post_id, current_user.username)
            flash("收藏成功" if added else "文章已在收藏夹中", "success" if added else "info")
            if added:
                _notify_system(f"用户 {current_user.username} 收藏文章《{title_display}》")
    except ValueError:
        flash("未找到文章，无法进行收藏操作", "error")
        return redirect(url_for("blog.index"))
    return redirect(next_url)


@bp.route("/favorites")
@login_required
def favorites():
    datastore = get_datastore()
    user_map = _user_lookup(datastore)
    raw_posts = datastore.list_favorite_posts(current_user.username)
    favorite_post_ids = {post["id"] for post in raw_posts}
    posts = [_decorate_post(post, user_map, favorite_post_ids) for post in raw_posts]
    return render_template(
        "blog/favorites.html",
        posts=posts,
    )


@bp.route("/post/<post_id>/comments/<comment_id>/delete", methods=["POST"])
@login_required
def delete_comment(post_id: str, comment_id: str):
    datastore = get_datastore()
    post = datastore.get_post(post_id)
    if not post:
        abort(404)
    comment = None
    for item in post.get("comments", []):
        if item.get("id") == comment_id:
            comment = item
            break
    if comment is None:
        abort(404)
    if not (current_user.is_admin or comment.get("author") == current_user.username):
        flash("没有权限删除该评论", "error")
        return redirect(url_for("blog.detail", post_id=post_id))
    try:
        datastore.delete_comment(post_id, comment_id)
    except ValueError:
        flash("评论不存在或已删除", "error")
    else:
        flash("评论已删除", "success")
        title_display = post.get("title", "")
        title_display = title_display if len(title_display) <= 40 else title_display[:37] + "…"
        _notify_system(f"用户 {current_user.username} 删除了文章《{title_display}》的一条评论")
    return redirect(url_for("blog.detail", post_id=post_id))


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
            title_display = title if len(title) <= 40 else title[:37] + "…"
            _notify_system(f"用户 {current_user.username} 更新文章《{title_display}》")
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
    title_display = post.get("title", "")
    title_display = title_display if len(title_display) <= 40 else title_display[:37] + "…"
    _notify_system(f"用户 {current_user.username} 删除文章《{title_display}》")
    return redirect(url_for("blog.index"))


@bp.route("/user/<username>", methods=["GET", "POST"])
def user_profile(username: str):
    datastore = get_datastore()
    user_record = datastore.get_user(username)
    if not user_record:
        abort(404)

    can_edit_real_name = current_user.is_authenticated and current_user.is_admin
    common_tags = datastore.list_common_tags()
    common_tag_set = set(common_tags)
    selected_tags: List[str] = []
    seen_tags: Set[str] = set()
    for value in request.args.getlist("tag"):
        text = value.strip()
        if not text or text in seen_tags or text not in common_tag_set:
            continue
        seen_tags.add(text)
        selected_tags.append(text)

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
    raw_posts = [post for post in datastore.list_posts() if post.get("author") == username]
    if selected_tags:
        filtered_posts = []
        required = set(selected_tags)
        for post in raw_posts:
            post_tags = set(post.get("tags", []))
            if required.issubset(post_tags):
                filtered_posts.append(post)
        raw_posts = filtered_posts
    viewer_favorite_ids: Set[str] = set()
    if current_user.is_authenticated:
        viewer_favorite_ids = datastore.favorite_post_ids(
            current_user.username,
            [post["id"] for post in raw_posts],
        )
    user_posts = [_decorate_post(post, user_map, viewer_favorite_ids) for post in raw_posts]
    viewing_self = current_user.is_authenticated and current_user.username == username
    favorite_posts = []
    if viewing_self:
        favorites_raw = datastore.list_favorite_posts(username)
        owned_favorite_ids = {post["id"] for post in favorites_raw}
        favorite_posts = [_decorate_post(post, user_map, owned_favorite_ids) for post in favorites_raw]
    return render_template(
        "blog/user_profile.html",
        profile=user_record,
        posts=user_posts,
        can_edit_real_name=can_edit_real_name,
        viewing_self=viewing_self,
        favorite_posts=favorite_posts if viewing_self else None,
        common_tags=common_tags,
        selected_tags=selected_tags,
    )
