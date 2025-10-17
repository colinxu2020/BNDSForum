from __future__ import annotations

from typing import Dict, List, cast

from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from .datastore import (
    DataStore,
    MESSAGE_PREFERENCES,
    MESSAGE_PREFERENCE_DEFAULT,
    MessagePreference,
)


bp = Blueprint("messages", __name__, url_prefix="/messages")

_PREFERENCE_LABELS: Dict[MessagePreference, str] = {
    "notify": "收到消息时提醒",
    "silent": "收到消息时不提醒",
    "block": "拉黑对方",
}
_PREFERENCE_ORDER: List[MessagePreference] = ["notify", "silent", "block"]


def get_datastore() -> DataStore:
    return current_app.extensions["datastore"]


def _inbox_url(with_username: str | None = None) -> str:
    if with_username:
        return url_for("messages.inbox", **{"with": with_username})
    return url_for("messages.inbox")


def _display_name(record: Dict[str, object] | None, username: str) -> str:
    if not record:
        return username
    real_name = str(record.get("real_name") or "").strip()
    if real_name:
        return f"{real_name}（{username}）"
    return username


def _user_brief(datastore: DataStore, username: str) -> Dict[str, object]:
    record = datastore.get_user(username) or {}
    return {
        "username": username,
        "real_name": record.get("real_name", ""),
        "display": _display_name(record, username),
    }


@bp.route("/", methods=["GET"])
@login_required
def inbox():
    datastore = get_datastore()
    current_username = current_user.username
    conversations = datastore.list_conversations(current_username)
    selected_username = request.args.get("with", "").strip()
    query = request.args.get("q", "").strip()
    search_results: List[Dict[str, object]] = []
    if query:
        # exclude self from search results
        search_results = [
            {"username": item["username"], "display": _display_name(item, item["username"])}
            for item in datastore.search_users(query, limit=20)
            if item["username"] != current_username
        ]

    conversation_users = {item["user"] for item in conversations}
    if selected_username:
        conversation_users.add(selected_username)
    user_lookup = {username: datastore.get_user(username) or {} for username in conversation_users}

    enriched_conversations = []
    for item in conversations:
        username = item["user"]
        enriched_conversations.append(
            {
                "username": username,
                "display": _display_name(user_lookup.get(username), username),
                "last_message": item["last_message"],
                "unread_count": item["unread_count"],
                "preference": item["preference"],
            }
        )

    thread_messages: List[Dict[str, object]] = []
    selected_user_info: Dict[str, object] | None = None
    selected_preference: MessagePreference = MESSAGE_PREFERENCE_DEFAULT
    if selected_username:
        target_user = datastore.get_user(selected_username)
        if not target_user:
            flash("未找到目标用户", "error")
            return redirect(_inbox_url())
        thread_messages = [
            {
                **message,
                "is_outgoing": message["sender"] == current_username,
            }
            for message in datastore.get_conversation_messages(current_username, selected_username)
        ]
        datastore.mark_conversation_read(current_username, selected_username)
        selected_preference = datastore.get_message_preference(current_username, selected_username)
        selected_user_info = _user_brief(datastore, selected_username)

    preference_options = []
    for value in _PREFERENCE_ORDER:
        if value in MESSAGE_PREFERENCES:
            preference_options.append(
                {
                    "value": value,
                    "label": _PREFERENCE_LABELS[value],
                }
            )

    return render_template(
        "messages/inbox.html",
        conversations=enriched_conversations,
        selected_username=selected_username,
        messages=thread_messages,
        selected_user=selected_user_info,
        selected_preference=selected_preference,
        preference_options=sorted(preference_options, key=lambda item: item["value"]),
        search_query=query,
        search_results=search_results,
    )


@bp.route("/send", methods=["POST"])
@login_required
def send():
    datastore = get_datastore()
    recipient = (request.form.get("recipient") or "").strip()
    content = (request.form.get("content") or "").strip()
    if not recipient:
        flash("请选择要发送私信的用户", "error")
        return redirect(_inbox_url())
    if recipient == current_user.username:
        flash("不能给自己发送私信", "error")
        return redirect(_inbox_url(recipient))
    if not content:
        flash("私信内容不能为空", "error")
        return redirect(_inbox_url(recipient))
    try:
        datastore.send_private_message(current_user.username, recipient, content)
    except PermissionError:
        flash("对方已将你拉黑，无法发送消息", "error")
    except ValueError as exc:
        flash(str(exc), "error")
    else:
        flash("私信已发送", "success")
    return redirect(_inbox_url(recipient))


@bp.route("/preference/<username>", methods=["POST"])
@login_required
def update_preference(username: str):
    datastore = get_datastore()
    preference_value = (request.form.get("preference") or "").strip()
    if preference_value not in MESSAGE_PREFERENCES:
        flash("不支持的私信偏好", "error")
        return redirect(_inbox_url(username))
    try:
        datastore.set_message_preference(
            current_user.username,
            username,
            cast(MessagePreference, preference_value),
        )
    except ValueError as exc:
        flash(str(exc), "error")
    else:
        if preference_value == MESSAGE_PREFERENCE_DEFAULT:
            flash("已恢复默认提醒方式", "success")
        elif preference_value == "silent":
            flash("已设置为收到消息时不提醒", "success")
        elif preference_value == "block":
            flash("已拉黑该用户，后续消息将被拦截", "success")
        else:
            flash("已更新私信偏好", "success")
    return redirect(_inbox_url(username))
