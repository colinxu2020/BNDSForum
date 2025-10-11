from __future__ import annotations

from typing import Dict, List

from flask import Blueprint, abort, current_app, render_template
from flask_login import current_user

from .datastore import DataStore


bp = Blueprint("tag", __name__)


def get_datastore() -> DataStore:
    return current_app.extensions["datastore"]


def build_tree_map(tree: Dict) -> Dict[str, Dict]:
    nodes = {node["id"]: node for node in tree.get("nodes", [])}
    return nodes


def build_paths(tree: Dict) -> Dict[str, List[str]]:
    nodes = build_tree_map(tree)
    parents = {}
    for node in tree.get("nodes", []):
        for child in node.get("children", []):
            parents[child] = node["id"]

    paths: Dict[str, List[str]] = {}

    def collect(node_id: str) -> List[str]:
        node = nodes[node_id]
        tag = node.get("tag")
        if node_id == "root":
            paths[node_id] = []
        if node_id in paths:
            return paths[node_id]
        parent_id = parents.get(node_id, "root")
        parent_path = collect(parent_id)
        result = parent_path.copy()
        if tag:
            result.append(tag)
        paths[node_id] = result
        return result

    for node_id in nodes:
        collect(node_id)
    return paths


def build_hierarchy(tree: Dict) -> Dict:
    nodes = {node["id"]: {**node, "children": list(node.get("children", []))} for node in tree.get("nodes", [])}
    for node in nodes.values():
        node["children"] = [nodes[child_id] for child_id in node.get("children", []) if child_id in nodes]
    return nodes.get("root", {"id": "root", "tag": None, "children": []})


def compute_node_stats(datastore: DataStore, tree: Dict):
    paths = build_paths(tree)
    normal_tags = set(datastore.list_normal_tags())
    users = datastore.list_users()
    user_map = {user["username"]: user for user in users}
    stats = {}
    for node_id, tag_chain in paths.items():
        if not tag_chain:
            posts = datastore.list_posts()
        else:
            posts = datastore.posts_with_tags(tag_chain)
        decorated_posts = []
        for post in posts:
            author = post.get("author")
            record = user_map.get(author, {})
            decorated_post = {**post}
            decorated_post["author_username"] = author
            decorated_post["author_real_name"] = record.get("real_name", "")
            decorated_post["author_display"] = decorated_post["author_real_name"] or author
            decorated_posts.append(decorated_post)
        eligible_users = []
        required = set(tag_chain)
        for user in users:
            user_constant = set(user.get("constant_tags", []))
            available = user_constant | normal_tags
            if required.issubset(available):
                eligible_users.append(
                    {
                        "username": user["username"],
                        "real_name": user.get("real_name", ""),
                        "has_post": datastore.user_has_post_with_tags(user["username"], tag_chain),
                        "constant_tags": sorted(user_constant),
                    }
                )
        eligible_users.sort(
            key=lambda item: ((item.get("real_name") or item["username"]).lower(), item["username"].lower())
        )
        stats[node_id] = {
            "posts": decorated_posts,
            "eligible_users": eligible_users,
            "path_tags": tag_chain,
        }
    return stats


@bp.route("/")
def tree_view():
    datastore = get_datastore()
    tree = datastore.get_tag_tree()
    stats = compute_node_stats(datastore, tree)
    hierarchy = build_hierarchy(tree)
    return render_template(
        "tag/tree.html",
        hierarchy=hierarchy,
        stats=stats,
    )


@bp.route("/<node_id>")
def node_detail(node_id: str):
    datastore = get_datastore()
    tree = datastore.get_tag_tree()
    nodes = build_tree_map(tree)
    if node_id not in nodes:
        abort(404)
    stats = compute_node_stats(datastore, tree)
    node_stats = stats.get(node_id, {"posts": [], "eligible_users": [], "path_tags": []})
    node = nodes[node_id]
    return render_template(
        "tag/node.html",
        node=node,
        stats=node_stats,
        is_admin=getattr(current_user, "is_admin", False),
    )
