from __future__ import annotations

from typing import Any, Dict, List, Set

from flask import Blueprint, current_app, render_template, request

from .datastore import DataStore

bp = Blueprint("tag", __name__)


def get_datastore() -> DataStore:
    return current_app.extensions["datastore"]


@bp.route("/classes")
def class_overview():
    datastore = get_datastore()
    class_groups = datastore.list_class_groups()
    column_tags = datastore.list_column_tags()
    common_tags = datastore.list_common_tags()
    memberships = datastore.class_memberships()
    users = datastore.list_users()

    user_map = {user["username"]: user for user in users}
    membership_names: Dict[str, str] = {}
    for member_list in memberships.values():
        for member in member_list:
            username = member.get("username", "")
            real_name = (member.get("real_name") or "").strip()
            if username and real_name and username not in membership_names:
                membership_names[username] = real_name

    class_lookup = {group["tag"]: group for group in class_groups}
    class_tag_set = set(class_lookup.keys())
    column_tag_set = set(column_tags)
    common_tag_set = set(common_tags)

    def _normalize(values: List[str]) -> List[str]:
        seen: Set[str] = set()
        result: List[str] = []
        for value in values:
            text = (value or "").strip()
            if not text or text in seen:
                continue
            seen.add(text)
            result.append(text)
        return result

    selected_classes = [tag for tag in _normalize(request.args.getlist("classes")) if tag in class_tag_set]
    selected_columns = [tag for tag in _normalize(request.args.getlist("columns")) if tag in column_tag_set]
    selected_common_tag = request.args.get("common_tag", "").strip()
    if selected_common_tag and selected_common_tag not in common_tag_set:
        selected_common_tag = ""

    show_tag_picker = bool(selected_classes and selected_columns and not selected_common_tag)
    show_results = bool(selected_classes and selected_columns and selected_common_tag)

    post_index: Dict[str, Dict[str, Any]] = {}
    filtered_posts: List[Dict[str, Any]] = []
    class_status: Dict[str, Dict[str, List[Dict[str, str]]]] = {}

    if show_results:
        for class_tag in selected_classes:
            for column_tag in selected_columns:
                required_tags = [class_tag, column_tag, selected_common_tag]
                posts = datastore.posts_with_tags(required_tags)
                for post in posts:
                    entry = post_index.get(post["id"])
                    if entry is None:
                        entry = {**post, "matched_classes": set(), "matched_columns": set()}
                        post_index[post["id"]] = entry
                    entry["matched_classes"].add(class_tag)
                    entry["matched_columns"].add(column_tag)

        for entry in post_index.values():
            author = entry.get("author", "")
            real_name = membership_names.get(author) or user_map.get(author, {}).get("real_name", "")
            entry["author_username"] = author
            entry["author_real_name"] = real_name
            entry["author_display"] = real_name or author
            entry["matched_classes"] = sorted(
                entry["matched_classes"],
                key=lambda tag: (class_lookup.get(tag, {}).get("display_name") or tag),
            )
            entry["matched_columns"] = sorted(entry["matched_columns"])
            filtered_posts.append(entry)

        filtered_posts.sort(key=lambda item: item.get("created_at") or "", reverse=True)

        post_authors_by_class: Dict[str, Set[str]] = {}
        for entry in filtered_posts:
            author = entry.get("author", "")
            for class_tag in entry["matched_classes"]:
                post_authors_by_class.setdefault(class_tag, set()).add(author)

        for class_tag in selected_classes:
            members = memberships.get(class_tag, [])
            member_usernames = {record["username"] for record in members}
            completed: List[Dict[str, str]] = []
            pending: List[Dict[str, str]] = []
            seen_members: Set[str] = set()
            for member in members:
                username = member.get("username", "")
                if not username or username in seen_members:
                    continue
                seen_members.add(username)
                real_name = (member.get("real_name") or "").strip() or membership_names.get(username) or user_map.get(username, {}).get("real_name", "")
                record = {"username": username, "real_name": real_name}
                if username in post_authors_by_class.get(class_tag, set()):
                    completed.append(record)
                else:
                    pending.append(record)
            extra_authors = []
            for author in post_authors_by_class.get(class_tag, set()):
                if author in member_usernames:
                    continue
                real_name = membership_names.get(author) or user_map.get(author, {}).get("real_name", "")
                extra_authors.append({"username": author, "real_name": real_name})
            completed.sort(key=lambda item: (item["real_name"] or item["username"]))
            pending.sort(key=lambda item: (item["real_name"] or item["username"]))
            extra_authors.sort(key=lambda item: (item["real_name"] or item["username"]))
            class_status[class_tag] = {
                "completed": completed,
                "pending": pending,
                "extra_authors": extra_authors,
            }

    return render_template(
        "tag/classes.html",
        class_groups=class_groups,
        column_tags=column_tags,
        common_tags=common_tags,
        memberships=memberships,
        selected_classes=selected_classes,
        selected_columns=selected_columns,
        selected_common_tag=selected_common_tag,
        show_tag_picker=show_tag_picker,
        show_results=show_results,
        filtered_posts=filtered_posts,
        class_status=class_status,
        class_lookup=class_lookup,
    )

