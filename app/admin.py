from __future__ import annotations

import json
from typing import Dict, List, Tuple

from datetime import datetime, timezone
from io import BytesIO
import zipfile

from flask import Blueprint, current_app, flash, redirect, render_template, request, send_file, url_for
from flask_login import current_user, login_required

from .datastore import DataStore, DEFAULT_CATEGORY_TAG, DEFAULT_CLASS_TAG


bp = Blueprint("admin", __name__)


def get_datastore() -> DataStore:
    return current_app.extensions["datastore"]


def _notify_admins(message: str) -> None:
    datastore = get_datastore()
    try:
        datastore.send_system_notification(message)
    except Exception:  # pragma: no cover - best effort
        current_app.logger.exception("发送系统通知失败：%s", message)


@bp.before_request
def check_admin():
    if request.endpoint and request.endpoint.startswith("admin."):
        if not current_user.is_authenticated:
            return redirect(url_for("auth.login", next=request.url))
        if not current_user.is_admin:
            flash("需要管理员权限", "error")
            return redirect(url_for("blog.index"))


_INVALID_SEGMENT_CHARS = set('<>:"/\\|?*')


def _safe_segment(value: str, fallback: str) -> str:
    text = (value or "").strip()
    if not text:
        text = fallback
    cleaned_chars = []
    for char in text:
        if char in _INVALID_SEGMENT_CHARS or ord(char) < 32:
            cleaned_chars.append("_")
        else:
            cleaned_chars.append(char)
    sanitized = "".join(cleaned_chars).strip().replace(" ", "_")
    sanitized = sanitized.strip("._")
    if not sanitized:
        return fallback
    return sanitized


def _author_folder_name(username: str, user: Dict[str, object], seen: Dict[str, int]) -> str:
    fallback = f"user_{username}"
    username_safe = _safe_segment(username, fallback)
    real_name = str(user.get("real_name", "") or "").strip()
    if real_name:
        base = _safe_segment(real_name, fallback)
        if base != username_safe:
            base = f"{base}_{username_safe}"
        else:
            base = username_safe
    else:
        base = username_safe
    count = seen.get(base, 0) + 1
    seen[base] = count
    if count == 1:
        return base
    return f"{base}_{count}"


def _format_yaml_scalar(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    text = str(value)
    if "\n" in text or ":" in text:
        escaped = text.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    escaped = text.replace("\\", "\\\\").replace('"', '\\"')
    if escaped == "":
        return '""'
    return f'"{escaped}"'


def _dump_front_matter(entries: List[Tuple[str, object]]) -> str:
    lines: List[str] = []
    for key, value in entries:
        if isinstance(value, list):
            if not value:
                lines.append(f"{key}: []")
                continue
            lines.append(f"{key}:")
            for item in value:
                lines.append(f"  - {_format_yaml_scalar(item)}")
        else:
            lines.append(f"{key}: {_format_yaml_scalar(value)}")
    return "\n".join(lines)


def _post_filename(
    base: str,
    author_folder: str,
    created_at: str,
    counter: Dict[Tuple[str, str], int],
    fallback: str,
) -> str:
    date_prefix = (created_at or "").split("T", 1)[0] or "unknown-date"
    date_safe = _safe_segment(date_prefix, "unknown-date")
    base_safe = _safe_segment(base, fallback)
    if not base_safe:
        base_safe = fallback
    stem = f"{date_safe}_{base_safe}"
    key = (author_folder, stem.lower())
    index = counter.get(key, 0) + 1
    counter[key] = index
    if index == 1:
        return f"{stem}.md"
    return f"{stem}-{index}.md"


@bp.route("/")
@login_required
def dashboard():
    if not current_user.is_admin:
        return redirect(url_for("blog.index"))
    datastore = get_datastore()
    users = datastore.list_users()
    category_tags = datastore.list_category_tags()
    constant_tags = datastore.list_constant_tags()
    class_tags = datastore.list_class_tags(with_meta=True, auto_sync=True)
    return render_template(
        "admin/dashboard.html",
        users=users,
        category_tags=category_tags,
        constant_tags=constant_tags,
        class_tags=class_tags,
    )


@bp.route("/export/posts")
@login_required
def export_posts():
    if not current_user.is_admin:
        return redirect(url_for("blog.index"))
    datastore = get_datastore()
    posts = datastore.list_posts()
    users = {user["username"]: user for user in datastore.list_users()}
    author_buckets: Dict[str, List[Dict[str, object]]] = {}
    for post in posts:
        author = post.get("author") or "unknown"
        author_buckets.setdefault(author, []).append(post)
    folder_seen: Dict[str, int] = {}
    filename_counters: Dict[Tuple[str, str], int] = {}
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for author in sorted(author_buckets.keys()):
            post_list = author_buckets[author]
            post_list.sort(key=lambda item: ((item.get("created_at") or ""), item.get("id") or ""))
            user = users.get(author, {})
            folder_name = _author_folder_name(author, user, folder_seen)
            constant_tags = list(user.get("constant_tags", []) or [])
            real_name = str(user.get("real_name", "") or "")
            for post in post_list:
                title = post.get("title") or "untitled"
                filename = _post_filename(
                    title,
                    folder_name,
                    post.get("created_at") or "",
                    filename_counters,
                    f"post_{(post.get('id') or '')[:8] or 'unknown'}",
                )
                tags = sorted(post.get("tags", []) or [])
                front_matter_entries: List[Tuple[str, object]] = [
                    ("post_id", post.get("id") or ""),
                    ("title", title),
                    ("author", author),
                ]
                if real_name:
                    front_matter_entries.append(("author_real_name", real_name))
                front_matter_entries.extend(
                    [
                        ("created_at", post.get("created_at") or ""),
                        ("updated_at", post.get("updated_at") or ""),
                        ("category_tag", post.get("category_tag") or DEFAULT_CATEGORY_TAG),
                        ("class_tag", post.get("class_tag") or DEFAULT_CLASS_TAG),
                        ("tags", tags),
                    ]
                )
                if constant_tags:
                    front_matter_entries.append(("author_constant_tags", constant_tags))
                front_matter = _dump_front_matter(front_matter_entries)
                content_body = post.get("content") or ""
                combined = f"---\n{front_matter}\n---\n\n{content_body.rstrip()}\n"
                archive.writestr(f"{folder_name}/{filename}", combined.encode("utf-8"))
    buffer.seek(0)
    download_name = f"blog-export-{timestamp}.zip"
    return send_file(buffer, mimetype="application/zip", as_attachment=True, download_name=download_name)


@bp.route("/users")
@login_required
def user_list():
    if not current_user.is_admin:
        return redirect(url_for("blog.index"))
    datastore = get_datastore()
    all_users = datastore.list_users()
    catalog_constant = datastore.list_constant_tags()
    username_query = request.args.get("username", "").strip().lower()
    real_name_query = request.args.get("real_name", "").strip().lower()
    tag_params = [item.strip() for item in request.args.getlist("constant_tag") if item.strip()]
    if not tag_params:
        legacy_raw = request.args.get("constant_tag", "")
        if legacy_raw:
            tag_params = [item.strip() for item in legacy_raw.split(",") if item.strip()]
    selected_tags: List[str] = []
    seen_lower: set[str] = set()
    for item in tag_params:
        lowered = item.lower()
        if lowered in seen_lower:
            continue
        seen_lower.add(lowered)
        matched = next((tag for tag in catalog_constant if tag.lower() == lowered), item)
        selected_tags.append(matched)
    selected_tags.sort()
    selected_tags_lower = {tag.lower() for tag in selected_tags}

    filtered_users = []
    for user in all_users:
        username = user.get("username", "")
        real_name = user.get("real_name", "")
        constant_tags = user.get("constant_tags", [])
        if username_query and username_query not in username.lower():
            continue
        if real_name_query and real_name_query not in real_name.lower():
            continue
        if selected_tags_lower:
            normalized = {tag.lower() for tag in constant_tags}
            if not selected_tags_lower.issubset(normalized):
                continue
        filtered_users.append(user)

    filtered_users.sort(
        key=lambda item: ((item.get("real_name") or item["username"]).lower(), item["username"].lower())
    )

    return render_template(
        "admin/users.html",
        users=filtered_users,
        total_users=len(all_users),
        matched_count=len(filtered_users),
        filters={
            "username": request.args.get("username", "").strip(),
            "real_name": request.args.get("real_name", "").strip(),
            "constant_tags": selected_tags,
        },
        constant_tags=catalog_constant,
    )


@bp.route("/tags/add", methods=["POST"])
@login_required
def add_category_tag():
    if not current_user.is_admin:
        return redirect(url_for("blog.index"))
    tag_name = request.form.get("tag_name", "").strip()
    if not tag_name:
        flash("类别标签名称不能为空", "error")
    else:
        datastore = get_datastore()
        datastore.add_category_tag(tag_name)
        flash("类别标签已添加", "success")
        _notify_admins(f"管理员 {current_user.username} 新增类别标签：{tag_name}")
    return redirect(url_for("admin.dashboard"))


@bp.route("/tags/delete", methods=["POST"])
@login_required
def delete_category_tag():
    if not current_user.is_admin:
        return redirect(url_for("blog.index"))
    tag_name = request.form.get("tag_name", "").strip()
    if not tag_name:
        flash("未指定类别标签", "error")
        return redirect(url_for("admin.dashboard"))
    datastore = get_datastore()
    try:
        datastore.remove_category_tag(tag_name)
    except ValueError as exc:
        flash(str(exc), "error")
    else:
        flash("类别标签已删除", "success")
        _notify_admins(f"管理员 {current_user.username} 删除类别标签：{tag_name}")
    return redirect(url_for("admin.dashboard"))


@bp.route("/class-tags/add", methods=["POST"])
@login_required
def add_class_tag():
    if not current_user.is_admin:
        return redirect(url_for("blog.index"))
    tag_name = request.form.get("tag_name", "").strip()
    if not tag_name:
        flash("班级标签名称不能为空", "error")
    else:
        datastore = get_datastore()
        try:
            datastore.add_class_tag(tag_name, source="manual")
        except ValueError as exc:
            flash(str(exc), "error")
        else:
            flash("班级标签已添加", "success")
            _notify_admins(f"管理员 {current_user.username} 新增班级标签：{tag_name}")
    return redirect(url_for("admin.dashboard"))


@bp.route("/class-tags/delete", methods=["POST"])
@login_required
def delete_class_tag():
    if not current_user.is_admin:
        return redirect(url_for("blog.index"))
    tag_name = request.form.get("tag_name", "").strip()
    if not tag_name:
        flash("未指定班级标签", "error")
        return redirect(url_for("admin.dashboard"))
    datastore = get_datastore()
    class_tags = datastore.list_class_tags(with_meta=True)
    target = next((item for item in class_tags if item["name"] == tag_name), None)
    if target and target.get("source") == "oj":
        flash("OJ 同步的班级标签请在 OJ 中维护，如需隐藏可等待同步移除。", "error")
        return redirect(url_for("admin.dashboard"))
    if target and target.get("source") == "builtin" and tag_name == DEFAULT_CLASS_TAG:
        flash("默认班级标签不可删除", "error")
        return redirect(url_for("admin.dashboard"))
    datastore.remove_class_tag(tag_name)
    flash("班级标签已删除", "success")
    _notify_admins(f"管理员 {current_user.username} 删除班级标签：{tag_name}")
    return redirect(url_for("admin.dashboard"))


@bp.route("/constant-tags/add", methods=["POST"])
@login_required
def add_constant_tag():
    if not current_user.is_admin:
        return redirect(url_for("blog.index"))
    tag_name = request.form.get("tag_name", "").strip()
    if not tag_name:
        flash("固定标签名称不能为空", "error")
    else:
        datastore = get_datastore()
        try:
            inserted = datastore.add_constant_tag(tag_name)
        except ValueError as exc:
            flash(str(exc), "error")
        else:
            if inserted:
                flash("固定标签已添加", "success")
                _notify_admins(f"管理员 {current_user.username} 新增固定标签：{tag_name}")
            else:
                flash("固定标签已存在", "info")
    return redirect(url_for("admin.dashboard"))


@bp.route("/constant-tags/delete", methods=["POST"])
@login_required
def delete_constant_tag():
    if not current_user.is_admin:
        return redirect(url_for("blog.index"))
    tag_name = request.form.get("tag_name", "").strip()
    if not tag_name:
        flash("未指定固定标签", "error")
        return redirect(url_for("admin.dashboard"))
    datastore = get_datastore()
    try:
        datastore.remove_constant_tag(tag_name)
    except ValueError as exc:
        flash(str(exc), "error")
    else:
        flash("固定标签已删除", "success")
        _notify_admins(f"管理员 {current_user.username} 删除固定标签：{tag_name}")
    return redirect(url_for("admin.dashboard"))


@bp.route("/users/update", methods=["POST"])
@login_required
def update_user():
    if not current_user.is_admin:
        return redirect(url_for("blog.index"))
    username = request.form.get("username", "").strip()
    role = request.form.get("role", "user")
    real_name = request.form.get("real_name", "").strip()

    def _normalize_constants(raw_values: List[str]) -> list[str]:
        result: list[str] = []
        seen: set[str] = set()
        for value in raw_values:
            item = (value or "").strip()
            if not item:
                continue
            lowered = item.lower()
            if lowered in seen:
                continue
            seen.add(lowered)
            result.append(item)
        return result

    constant_tags: list[str] | None = None
    if "constant_tags_payload" in request.form:
        payload_raw = (request.form.get("constant_tags_payload") or "").strip()
        parsed: list[str] = []
        if payload_raw:
            try:
                decoded = json.loads(payload_raw)
            except json.JSONDecodeError:
                decoded = []
            if isinstance(decoded, list):
                parsed = [str(item) for item in decoded]
        constant_tags = _normalize_constants(parsed)
    elif "constant_tags" in request.form:
        fallback_raw = request.form.get("constant_tags", "")
        values = []
        if fallback_raw:
            values = [item for item in fallback_raw.split(",")]
        constant_tags = _normalize_constants(values)
    return_to = (request.form.get("return_to") or "").strip()
    if not username:
        flash("未指定用户", "error")
        return redirect(url_for("admin.user_list"))
    if not real_name:
        flash("真实姓名不能为空", "error")
        return redirect(url_for("admin.user_list"))
    datastore = get_datastore()
    users = datastore.list_users()
    target = next((item for item in users if item["username"] == username), None)
    if not target:
        flash("用户不存在", "error")
        return redirect(url_for("admin.user_list"))

    if constant_tags is not None:
        catalog_set = {tag.lower() for tag in datastore.list_constant_tags()}
        invalid = [tag for tag in constant_tags if tag.lower() not in catalog_set]
        if invalid:
            flash(f"存在未登记的固定标签：{', '.join(invalid)}", "error")
            return redirect(url_for("admin.user_list"))

    current_role = target.get("role", "user")
    if current_role == "admin" and role != "admin":
        admin_count = sum(1 for item in users if item.get("role") == "admin")
        if admin_count <= 1:
            flash("至少保留一位管理员", "error")
            return redirect(url_for("admin.user_list"))
    datastore.update_user_real_name(username, real_name)
    if constant_tags is not None:
        datastore.update_user_constant_tags(username, constant_tags)
    datastore.set_user_role(username, role)
    flash("用户信息已更新", "success")
    _notify_admins(
        f"管理员 {current_user.username} 更新用户 {username} 信息：角色={role}，真实姓名={real_name}"
    )
    fallback = url_for("admin.user_list")
    redirect_target = fallback
    if return_to and return_to.startswith(fallback):
        redirect_target = return_to
    return redirect(redirect_target)


@bp.route("/users/<username>/ban", methods=["POST"])
@login_required
def ban_user(username: str):
    if not current_user.is_admin:
        return redirect(url_for("blog.index"))
    target_username = (username or "").strip()
    return_to = (request.form.get("return_to") or "").strip()
    fallback = url_for("admin.user_list")
    redirect_target = fallback
    if return_to and return_to.startswith(fallback):
        redirect_target = return_to
    if not target_username:
        flash("未指定用户", "error")
        return redirect(redirect_target)
    if target_username == current_user.username:
        flash("不能封禁当前登录账号", "error")
        return redirect(redirect_target)
    datastore = get_datastore()
    target = datastore.get_user(target_username)
    if not target:
        flash("用户不存在", "error")
        return redirect(redirect_target)
    if target.get("is_banned"):
        flash("用户已处于封禁状态", "info")
        return redirect(redirect_target)
    if target.get("role") == "admin":
        users = datastore.list_users()
        active_admins = [
            user for user in users if user.get("role") == "admin" and not user.get("is_banned")
        ]
        if len(active_admins) <= 1 and any(user["username"] == target_username for user in active_admins):
            flash("至少保留一位未被封禁的管理员", "error")
            return redirect(redirect_target)
    try:
        datastore.set_user_banned(target_username, True)
    except ValueError as exc:
        flash(str(exc), "error")
    else:
        flash("用户已封禁", "success")
        _notify_admins(f"管理员 {current_user.username} 封禁用户：{target_username}")
    return redirect(redirect_target)


@bp.route("/users/<username>/unban", methods=["POST"])
@login_required
def unban_user(username: str):
    if not current_user.is_admin:
        return redirect(url_for("blog.index"))
    target_username = (username or "").strip()
    return_to = (request.form.get("return_to") or "").strip()
    fallback = url_for("admin.user_list")
    redirect_target = fallback
    if return_to and return_to.startswith(fallback):
        redirect_target = return_to
    if not target_username:
        flash("未指定用户", "error")
        return redirect(redirect_target)
    datastore = get_datastore()
    target = datastore.get_user(target_username)
    if not target:
        flash("用户不存在", "error")
        return redirect(redirect_target)
    if not target.get("is_banned"):
        flash("用户当前未被封禁", "info")
        return redirect(redirect_target)
    try:
        datastore.set_user_banned(target_username, False)
    except ValueError as exc:
        flash(str(exc), "error")
    else:
        flash("用户已解封", "success")
        _notify_admins(f"管理员 {current_user.username} 解封用户：{target_username}")
    return redirect(redirect_target)


@bp.route("/users/tags/bulk", methods=["POST"])
@login_required
def bulk_update_user_tags():
    if not current_user.is_admin:
        return redirect(url_for("blog.index"))
    operation = request.form.get("operation", "add").strip().lower()
    if operation not in {"add", "remove"}:
        flash("不支持的操作类型", "error")
        return redirect(url_for("admin.user_list"))
    raw_tags = [item.strip() for item in request.form.getlist("tags") if item.strip()]
    if not raw_tags:
        flash("请选择至少一个固定标签", "error")
        return redirect(url_for("admin.user_list"))
    raw_users = [item.strip() for item in request.form.getlist("usernames") if item.strip()]
    if not raw_users:
        flash("请选择要操作的用户", "error")
        return redirect(url_for("admin.user_list"))

    datastore = get_datastore()
    catalog = datastore.list_constant_tags()
    catalog_map = {tag.lower(): tag for tag in catalog}
    selected_tags: List[str] = []
    selected_lower: set[str] = set()
    for tag in raw_tags:
        lowered = tag.lower()
        if lowered in selected_lower:
            continue
        if lowered not in catalog_map:
            flash(f"固定标签不存在：{tag}", "error")
            return redirect(url_for("admin.user_list"))
        selected_lower.add(lowered)
        selected_tags.append(catalog_map[lowered])

    user_map = {user["username"]: user for user in datastore.list_users()}
    missing_users = [username for username in raw_users if username not in user_map]
    if missing_users:
        flash(f"以下用户不存在：{', '.join(missing_users)}", "error")
        return redirect(url_for("admin.user_list"))

    usernames: List[str] = []
    seen_users: set[str] = set()
    for username in raw_users:
        if username in seen_users:
            continue
        seen_users.add(username)
        usernames.append(username)

    updated_count = 0
    for username in usernames:
        record = user_map[username]
        current_tags = record.get("constant_tags", [])
        if operation == "add":
            current_lower = {tag.lower() for tag in current_tags}
            next_tags = list(current_tags)
            for tag in selected_tags:
                if tag.lower() not in current_lower:
                    next_tags.append(tag)
                    current_lower.add(tag.lower())
            changed = len(next_tags) != len(current_tags)
        else:
            next_tags = [tag for tag in current_tags if tag.lower() not in selected_lower]
            changed = len(next_tags) != len(current_tags)
        if not changed:
            continue
        datastore.update_user_constant_tags(username, next_tags)
        updated_count += 1

    if updated_count:
        action_label = "添加" if operation == "add" else "移除"
        flash(f"已为 {updated_count} 位用户{action_label}固定标签", "success")
        _notify_admins(
            f"管理员 {current_user.username}{action_label}固定标签 {', '.join(selected_tags)} 给 {updated_count} 位用户"
        )
    else:
        flash("选中的用户无需更新固定标签", "info")

    fallback = url_for("admin.user_list")
    return_to = (request.form.get("return_to") or "").strip()
    redirect_target = fallback
    if return_to and return_to.startswith(fallback):
        redirect_target = return_to
    return redirect(redirect_target)
