from __future__ import annotations

from typing import Dict, List

from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from .datastore import DataStore


bp = Blueprint("admin", __name__)


def get_datastore() -> DataStore:
    return current_app.extensions["datastore"]


@bp.before_request
def check_admin():
    if request.endpoint and request.endpoint.startswith("admin."):
        if not current_user.is_authenticated:
            return redirect(url_for("auth.login", next=request.url))
        if not current_user.is_admin:
            flash("需要管理员权限", "error")
            return redirect(url_for("blog.index"))


def _build_parent_choices(tag_tree: Dict) -> List[Dict[str, str]]:
    nodes = {node["id"]: node for node in tag_tree.get("nodes", [])}
    parents = {}
    for node in tag_tree.get("nodes", []):
        for child in node.get("children", []):
            parents[child] = node["id"]

    def path_tags(node_id: str) -> List[str]:
        tags: List[str] = []
        current = node_id
        while current and current != "root":
            node = nodes.get(current)
            if node and node.get("tag"):
                tags.append(node["tag"])
            current = parents.get(current)
        tags.reverse()
        return tags

    choices: List[Dict[str, str]] = []
    for node_id in nodes:
        tags = path_tags(node_id)
        label = "根节点"
        if tags:
            label = "根节点 / " + " / ".join(tags)
        choices.append({"id": node_id, "label": label})
    choices.sort(key=lambda item: item["label"])
    return choices


def _build_tree_rows(tag_tree: Dict) -> List[Dict[str, str]]:
    nodes = {node["id"]: node for node in tag_tree.get("nodes", [])}
    parents = {}
    for node in tag_tree.get("nodes", []):
        for child in node.get("children", []):
            parents[child] = node["id"]

    def path(node_id: str) -> List[str]:
        result: List[str] = []
        current = node_id
        while current and current != "root":
            node = nodes.get(current)
            if node and node.get("tag"):
                result.append(node["tag"])
            current = parents.get(current)
        result.reverse()
        return result

    rows: List[Dict[str, str]] = []
    for node_id, node in nodes.items():
        rows.append(
            {
                "id": node_id,
                "tag": node.get("tag"),
                "path": path(node_id),
                "is_root": node_id == "root",
            }
        )
    rows.sort(key=lambda item: (0 if item["is_root"] else 1, item["path"]))
    return rows


@bp.route("/")
@login_required
def dashboard():
    if not current_user.is_admin:
        return redirect(url_for("blog.index"))
    datastore = get_datastore()
    users = datastore.list_users()
    normal_tags = datastore.list_normal_tags()
    tag_tree = datastore.get_tag_tree()
    parent_choices = _build_parent_choices(tag_tree)
    tree_rows = _build_tree_rows(tag_tree)
    return render_template(
        "admin/dashboard.html",
        users=users,
        normal_tags=normal_tags,
        parent_choices=parent_choices,
        tree_rows=tree_rows,
    )


@bp.route("/users")
@login_required
def user_list():
    if not current_user.is_admin:
        return redirect(url_for("blog.index"))
    datastore = get_datastore()
    all_users = datastore.list_users()
    username_query = request.args.get("username", "").strip().lower()
    real_name_query = request.args.get("real_name", "").strip().lower()
    constant_query_raw = request.args.get("constant_tag", "").strip()
    constant_terms = [item.lower() for item in constant_query_raw.split(",") if item.strip()]

    filtered_users = []
    for user in all_users:
        username = user.get("username", "")
        real_name = user.get("real_name", "")
        constant_tags = user.get("constant_tags", [])
        if username_query and username_query not in username.lower():
            continue
        if real_name_query and real_name_query not in real_name.lower():
            continue
        if constant_terms:
            normalized = [tag.lower() for tag in constant_tags]
            if not all(term in normalized for term in constant_terms):
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
            "constant_tag": constant_query_raw,
        },
        normal_tags=datastore.list_normal_tags(),
    )


@bp.route("/tags/add", methods=["POST"])
@login_required
def add_normal_tag():
    if not current_user.is_admin:
        return redirect(url_for("blog.index"))
    tag_name = request.form.get("tag_name", "").strip()
    if not tag_name:
        flash("标签名称不能为空", "error")
    else:
        datastore = get_datastore()
        datastore.add_normal_tag(tag_name)
        flash("标签已添加", "success")
    return redirect(url_for("admin.dashboard"))


@bp.route("/tags/delete", methods=["POST"])
@login_required
def delete_normal_tag():
    if not current_user.is_admin:
        return redirect(url_for("blog.index"))
    tag_name = request.form.get("tag_name", "").strip()
    if not tag_name:
        flash("未指定标签", "error")
        return redirect(url_for("admin.dashboard"))
    datastore = get_datastore()
    datastore.remove_normal_tag(tag_name)
    flash("标签已删除", "success")
    return redirect(url_for("admin.dashboard"))


@bp.route("/tree/add", methods=["POST"])
@login_required
def add_tree_node():
    if not current_user.is_admin:
        return redirect(url_for("blog.index"))
    parent_id = request.form.get("parent_id", "")
    tag = request.form.get("tag", "").strip() or None
    if not parent_id:
        flash("请选择父节点", "error")
    else:
        datastore = get_datastore()
        try:
            datastore.add_tree_node(parent_id, tag)
        except ValueError as exc:
            flash(str(exc), "error")
        else:
            flash("节点已创建", "success")
    return redirect(url_for("admin.dashboard"))


@bp.route("/tree/update", methods=["POST"])
@login_required
def update_tree_node():
    if not current_user.is_admin:
        return redirect(url_for("blog.index"))
    node_id = request.form.get("node_id", "")
    tag = request.form.get("tag", "").strip() or None
    if not node_id:
        flash("未指定节点", "error")
    elif node_id == "root" and tag is not None:
        flash("根节点不能设置标签", "error")
    else:
        datastore = get_datastore()
        try:
            datastore.update_tree_node(node_id, tag=tag)
        except ValueError as exc:
            flash(str(exc), "error")
        else:
            flash("节点已更新", "success")
    return redirect(url_for("admin.dashboard"))


@bp.route("/tree/delete", methods=["POST"])
@login_required
def delete_tree_node():
    if not current_user.is_admin:
        return redirect(url_for("blog.index"))
    node_id = request.form.get("node_id", "")
    if not node_id:
        flash("未指定节点", "error")
    else:
        datastore = get_datastore()
        try:
            datastore.remove_tree_node(node_id)
        except ValueError as exc:
            flash(str(exc), "error")
        else:
            flash("节点已删除", "success")
    return redirect(url_for("admin.dashboard"))


@bp.route("/users/update", methods=["POST"])
@login_required
def update_user():
    if not current_user.is_admin:
        return redirect(url_for("blog.index"))
    username = request.form.get("username", "").strip()
    role = request.form.get("role", "user")
    real_name = request.form.get("real_name", "").strip()
    constant_raw = [tag.strip() for tag in request.form.get("constant_tags", "").split(",") if tag.strip()]
    constant_tags: list[str] = []
    seen_tags: set[str] = set()
    for tag in constant_raw:
        lowered = tag.lower()
        if lowered in seen_tags:
            continue
        seen_tags.add(lowered)
        constant_tags.append(tag)
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

    current_role = target.get("role", "user")
    if current_role == "admin" and role != "admin":
        admin_count = sum(1 for item in users if item.get("role") == "admin")
        if admin_count <= 1:
            flash("至少保留一位管理员", "error")
            return redirect(url_for("admin.user_list"))
    datastore.update_user_real_name(username, real_name)
    datastore.update_user_constant_tags(username, constant_tags)
    datastore.set_user_role(username, role)
    flash("用户信息已更新", "success")
    fallback = url_for("admin.user_list")
    redirect_target = fallback
    if return_to and return_to.startswith(fallback):
        redirect_target = return_to
    return redirect(redirect_target)
