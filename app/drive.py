"""Cloud drive (云盘) blueprint."""
from __future__ import annotations

import logging
import os
import re
import secrets
from pathlib import Path

from flask import (
    Blueprint, abort, current_app, flash, jsonify, redirect,
    render_template, request, send_from_directory, url_for,
)
from flask_login import current_user, login_required
from werkzeug.utils import secure_filename

from .datastore import DataStore

bp = Blueprint("drive", __name__, url_prefix="/drive")
logger = logging.getLogger(__name__)

MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB per file


def get_datastore() -> DataStore:
    return current_app.extensions["datastore"]


def _drive_dir() -> Path:
    base = Path(current_app.root_path).parent / "data" / "drive"
    base.mkdir(parents=True, exist_ok=True)
    return base


def _user_drive_dir(username: str) -> Path:
    safe = re.sub(r"[^a-zA-Z0-9_-]", "_", username)[:64]
    d = _drive_dir() / safe
    d.mkdir(parents=True, exist_ok=True)
    return d


# File extensions that must NOT be stored (could be served as executable content).
_BLOCKED_DRIVE_EXTENSIONS = frozenset({
    "html", "htm", "xhtml", "js", "mjs", "cjs",
    "php", "php3", "php4", "php5", "phtml",
    "py", "pyc", "pyo",
    "sh", "bash", "zsh", "fish",
    "exe", "com", "bat", "cmd", "ps1", "psm1", "psd1",
    "vbs", "vbe", "jse", "wsf", "wsh",
    "jar", "war", "class",
    "svg", "svgz",
    "xml",
})


def _safe_filename(original: str) -> str:
    ext = original.rsplit(".", 1)[1].lower() if "." in original else "bin"
    return f"{secrets.token_hex(16)}.{ext}"


def _format_size(size: int) -> str:
    if size < 1024:
        return f"{size} B"
    elif size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    elif size < 1024 * 1024 * 1024:
        return f"{size / 1024 / 1024:.1f} MB"
    return f"{size / 1024 / 1024 / 1024:.2f} GB"


# ─── Routes ───

@bp.route("/")
@login_required
def index():
    datastore = get_datastore()
    parent_id = request.args.get("folder")
    files = datastore.list_drive_files(current_user.username, parent_id)
    path = datastore.get_drive_path(parent_id) if parent_id else []
    quota = datastore.get_user_quota(current_user.username)
    used = datastore.get_user_used_space(current_user.username)
    return render_template(
        "drive/index.html",
        files=files,
        path=path,
        parent_id=parent_id,
        quota=quota,
        used=used,
        format_size=_format_size,
    )


@bp.route("/api/upload", methods=["POST"])
@login_required
def api_upload():
    datastore = get_datastore()
    parent_id = request.form.get("parent_id") or None

    if "file" not in request.files:
        return jsonify({"success": False, "message": "未选择文件"}), 400

    file = request.files["file"]
    if not file or not file.filename:
        return jsonify({"success": False, "message": "文件为空"}), 400

    original_name = file.filename.strip()
    if not original_name:
        return jsonify({"success": False, "message": "文件名为空"}), 400

    # Sanitize
    original_name = secure_filename(original_name) or "file"

    # Block dangerous file extensions that could execute in-browser
    ext = original_name.rsplit(".", 1)[1].lower() if "." in original_name else ""
    if ext in _BLOCKED_DRIVE_EXTENSIONS:
        return jsonify({"success": False, "message": f".{ext} 类型文件暂不支持上传（安全限制）"}), 400

    file_data = file.read()
    file_size = len(file_data)

    if file_size > MAX_FILE_SIZE:
        return jsonify({"success": False, "message": f"文件过大，最大 {MAX_FILE_SIZE // 1024 // 1024} MB"}), 400

    if file_size == 0:
        return jsonify({"success": False, "message": "文件内容为空"}), 400

    # Pre-upload quota check
    if not datastore.check_quota(current_user.username, file_size):
        return jsonify({"success": False, "message": "存储空间不足"}), 400

    safe_name = _safe_filename(original_name)
    target = _user_drive_dir(current_user.username) / safe_name
    target.write_bytes(file_data)

    mime_type = file.content_type or "application/octet-stream"
    record = datastore.add_drive_file(
        username=current_user.username,
        filename=safe_name,
        original_name=original_name,
        mime_type=mime_type,
        file_size=file_size,
        parent_id=parent_id,
    )

    return jsonify({"success": True, "data": record})


@bp.route("/api/mkdir", methods=["POST"])
@login_required
def api_mkdir():
    datastore = get_datastore()
    name = (request.form.get("name") or "").strip()
    parent_id = request.form.get("parent_id") or None

    if not name:
        return jsonify({"success": False, "message": "文件夹名不能为空"}), 400
    if len(name) > 200:
        return jsonify({"success": False, "message": "文件夹名过长"}), 400
    if any(c in name for c in '/\\<>:"|?*'):
        return jsonify({"success": False, "message": "文件夹名包含非法字符"}), 400

    try:
        record = datastore.add_drive_file(
            username=current_user.username,
            filename="",
            original_name=name,
            mime_type="folder",
            file_size=0,
            parent_id=parent_id,
            is_folder=True,
        )
    except ValueError as exc:
        return jsonify({"success": False, "message": str(exc)}), 400

    return jsonify({"success": True, "data": record})


@bp.route("/api/rename", methods=["POST"])
@login_required
def api_rename():
    datastore = get_datastore()
    file_id = request.form.get("id", "").strip()
    new_name = request.form.get("name", "").strip()

    if not file_id or not new_name:
        return jsonify({"success": False, "message": "参数不完整"}), 400

    # Validate new name
    if len(new_name) > 200:
        return jsonify({"success": False, "message": "文件名过长（最多 200 字符）"}), 400
    if new_name in (".", ".."):
        return jsonify({"success": False, "message": "文件名非法"}), 400
    if any(c in new_name for c in '/\\<>:"|?*\x00'):
        return jsonify({"success": False, "message": "文件名包含非法字符"}), 400

    record = datastore.get_drive_file(file_id)
    if not record or record["username"] != current_user.username:
        return jsonify({"success": False, "message": "文件不存在"}), 404

    datastore.rename_drive_file(file_id, new_name)
    return jsonify({"success": True})


@bp.route("/api/delete", methods=["POST"])
@login_required
def api_delete():
    datastore = get_datastore()
    file_id = request.form.get("id", "").strip()

    if not file_id:
        return jsonify({"success": False, "message": "缺少文件 ID"}), 400

    record = datastore.get_drive_file(file_id)
    if not record:
        return jsonify({"success": False, "message": "文件不存在"}), 404
    if record["username"] != current_user.username and not current_user.is_admin:
        return jsonify({"success": False, "message": "无权操作"}), 403

    # Delete actual files (not folders)
    if not record["is_folder"] and record["filename"]:
        try:
            path = _user_drive_dir(record["username"]) / record["filename"]
            if path.exists():
                path.unlink()
        except OSError:
            logger.warning("删除云盘文件失败: %s", record["filename"])

    deleted = datastore.delete_drive_file(file_id)
    return jsonify({"success": True})


@bp.route("/download/<file_id>")
@login_required
def download(file_id: str):
    datastore = get_datastore()
    record = datastore.get_drive_file(file_id)
    if not record:
        abort(404)
    if record["username"] != current_user.username and not current_user.is_admin:
        abort(403)
    if record["is_folder"]:
        abort(400)

    user_dir = _user_drive_dir(record["username"])
    safe_file = secure_filename(record["filename"])
    if not safe_file:
        abort(404)

    target = (user_dir / safe_file).resolve()
    if not str(target).startswith(str(user_dir.resolve())):
        abort(403)

    return send_from_directory(
        str(user_dir), safe_file,
        as_attachment=True,
        download_name=record["original_name"],
    )
