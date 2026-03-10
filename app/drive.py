"""Cloud drive (云盘) blueprint."""
from __future__ import annotations

import logging
import os
import re
import secrets
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path

from flask import (
    Blueprint, Response, abort, current_app, flash, jsonify, redirect,
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


def _parse_share_expiry(value: str | None) -> str | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError("过期时间格式无效") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    if dt <= datetime.now(timezone.utc):
        raise ValueError("过期时间必须晚于当前时间")
    return dt.strftime("%Y-%m-%dT%H:%M:%S")


def _share_expired(share: dict) -> bool:
    if not share.get("expires_at"):
        return False
    try:
        exp = datetime.strptime(share["expires_at"], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return False
    return datetime.now(timezone.utc) > exp


def _share_limit_reached(share: dict) -> bool:
    max_downloads = share.get("max_downloads")
    if max_downloads in (None, "", 0):
        return False
    try:
        return int(share.get("download_count") or 0) >= int(max_downloads)
    except (TypeError, ValueError):
        return False


def _request_ip() -> str | None:
    forwarded = (request.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
    return forwarded or request.remote_addr


def _log_share_event(datastore: DataStore, share_id: str, access_type: str, access_status: str) -> None:
    username = current_user.username if getattr(current_user, "is_authenticated", False) else None
    datastore.log_drive_share_access(
        share_id=share_id,
        access_type=access_type,
        access_status=access_status,
        username=username,
        ip_address=_request_ip(),
        user_agent=request.headers.get("User-Agent"),
    )


def _share_status(share: dict) -> str:
    if _share_expired(share):
        return "expired"
    if _share_limit_reached(share):
        return "limit_reached"
    return "active"


def _serialize_share(share: dict, *, include_external: bool = True) -> dict:
    token = share["share_token"]
    share_url = url_for("drive.share_page", token=token, _external=include_external)
    qr_url = url_for("drive.share_qr", token=token, _external=include_external)
    return {
        **share,
        "share_url": share_url,
        "qr_url": qr_url,
        "status": _share_status(share),
        "require_login": bool(share.get("require_login")),
        "download_count": int(share.get("download_count") or 0),
        "max_downloads": int(share["max_downloads"]) if share.get("max_downloads") not in (None, "") else None,
    }


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


@bp.route("/shares")
@login_required
def shares():
    datastore = get_datastore()
    share_rows = datastore.list_drive_owner_shares(current_user.username)
    serialized = [_serialize_share(row, include_external=True) for row in share_rows]
    stats = {
        "total": len(serialized),
        "active": sum(1 for item in serialized if item["status"] == "active"),
        "expired": sum(1 for item in serialized if item["status"] == "expired"),
        "limited": sum(1 for item in serialized if item["status"] == "limit_reached"),
        "downloads": sum(int(item.get("download_count") or 0) for item in serialized),
    }
    return render_template(
        "drive/shares.html",
        shares=serialized,
        stats=stats,
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
    except ValueError:
        return jsonify({"success": False, "message": "请求失败或输入无效"}), 400

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

    pass

    return send_from_directory(
        str(user_dir), safe_file,
        as_attachment=True,
        download_name=record["original_name"],
    )


# ─── Share Routes ───


@bp.route("/api/share", methods=["POST"])
@login_required
def api_create_share():
    """Create a share link for a file."""
    datastore = get_datastore()
    file_id = request.form.get("file_id", "").strip()
    invite_code = request.form.get("invite_code", "").strip() or None
    expires_at_input = request.form.get("expires_at", "").strip()
    max_downloads_input = request.form.get("max_downloads", "").strip()
    require_login = request.form.get("require_login", "").strip() in {"1", "true", "on", "yes"}

    if not file_id:
        return jsonify({"success": False, "message": "缺少文件 ID"}), 400

    record = datastore.get_drive_file(file_id)
    if not record:
        return jsonify({"success": False, "message": "文件不存在"}), 404
    if record["username"] != current_user.username:
        return jsonify({"success": False, "message": "无权操作"}), 403
    if record["is_folder"]:
        return jsonify({"success": False, "message": "暂不支持文件夹分享"}), 400

    if invite_code and len(invite_code) > 32:
        return jsonify({"success": False, "message": "邀请码过长（最多 32 字符）"}), 400

    try:
        expires_at = _parse_share_expiry(expires_at_input)
    except ValueError:
        return jsonify({"success": False, "message": "请求失败或输入无效"}), 400

    max_downloads = None
    if max_downloads_input:
        try:
            max_downloads = int(max_downloads_input)
            if max_downloads < 1 or max_downloads > 100000:
                raise ValueError
        except (TypeError, ValueError):
            return jsonify({"success": False, "message": "下载次数必须是 1-100000 的整数"}), 400

    share = datastore.create_drive_share(
        file_id=file_id,
        owner_username=current_user.username,
        invite_code=invite_code,
        expires_at=expires_at,
        max_downloads=max_downloads,
        require_login=require_login,
    )
    serialized = _serialize_share(share)
    return jsonify({
        "success": True,
        "share_url": serialized["share_url"],
        "invite_code": invite_code,
        "qr_url": serialized["qr_url"],
        "data": serialized,
    })


@bp.route("/api/share/update", methods=["POST"])
@login_required
def api_update_share():
    datastore = get_datastore()
    share_id = request.form.get("share_id", "").strip()
    invite_code = request.form.get("invite_code", "").strip() or None
    expires_at_input = request.form.get("expires_at", "").strip()
    max_downloads_input = request.form.get("max_downloads", "").strip()
    require_login = request.form.get("require_login", "").strip() in {"1", "true", "on", "yes"}

    if not share_id:
        return jsonify({"success": False, "message": "缺少分享 ID"}), 400
    if invite_code and len(invite_code) > 32:
        return jsonify({"success": False, "message": "邀请码过长（最多 32 字符）"}), 400

    try:
        expires_at = _parse_share_expiry(expires_at_input)
    except ValueError:
        return jsonify({"success": False, "message": "请求失败或输入无效"}), 400

    max_downloads = None
    if max_downloads_input:
        try:
            max_downloads = int(max_downloads_input)
            if max_downloads < 1 or max_downloads > 100000:
                raise ValueError
        except (TypeError, ValueError):
            return jsonify({"success": False, "message": "下载次数必须是 1-100000 的整数"}), 400

    updated = datastore.update_drive_share(
        share_id=share_id,
        owner_username=current_user.username,
        invite_code=invite_code,
        expires_at=expires_at,
        max_downloads=max_downloads,
        require_login=require_login,
    )
    if not updated:
        return jsonify({"success": False, "message": "分享不存在或无权操作"}), 404
    return jsonify({"success": True, "data": _serialize_share(updated)})


@bp.route("/api/shares/<file_id>", methods=["GET"])
@login_required
def api_list_shares(file_id: str):
    """List all shares for a file."""
    datastore = get_datastore()
    record = datastore.get_drive_file(file_id)
    if not record:
        return jsonify({"success": False, "message": "文件不存在"}), 404
    if record["username"] != current_user.username:
        return jsonify({"success": False, "message": "无权操作"}), 403

    shares = datastore.get_drive_file_shares(file_id, current_user.username)
    result = [_serialize_share(s) for s in shares]
    return jsonify({"success": True, "data": result})


@bp.route("/api/share/logs/<share_id>", methods=["GET"])
@login_required
def api_share_logs(share_id: str):
    datastore = get_datastore()
    logs = datastore.list_drive_share_access_logs(share_id, current_user.username, limit=100)
    return jsonify({"success": True, "data": logs})


@bp.route("/api/share/delete", methods=["POST"])
@login_required
def api_delete_share():
    """Revoke/delete a share link."""
    datastore = get_datastore()
    share_id = request.form.get("share_id", "").strip()
    if not share_id:
        return jsonify({"success": False, "message": "缺少分享 ID"}), 400
    ok = datastore.delete_drive_share(share_id, current_user.username)
    if not ok:
        return jsonify({"success": False, "message": "分享不存在或无权操作"}), 404
    return jsonify({"success": True})


@bp.route("/share/<token>")
def share_page(token: str):
    """Public share landing page."""
    datastore = get_datastore()
    share = datastore.get_drive_share_by_token(token)
    if not share:
        abort(404)

    if _share_expired(share):
        _log_share_event(datastore, share["id"], "view", "expired")
        return render_template("drive/share.html", expired=True, exhausted=False, share=None, file=None)

    if _share_limit_reached(share):
        _log_share_event(datastore, share["id"], "view", "limit_reached")
        return render_template("drive/share.html", expired=False, exhausted=True, share=share, file=None)

    file_record = datastore.get_drive_file(share["file_id"])
    if not file_record:
        abort(404)

    _log_share_event(datastore, share["id"], "view", "success")

    needs_code = bool(share["invite_code"])
    return render_template(
        "drive/share.html",
        share=share,
        file=file_record,
        needs_code=needs_code,
        expired=False,
        exhausted=False,
        require_login=bool(share.get("require_login")),
        qr_url=url_for("drive.share_qr", token=token),
        format_size=_format_size,
        token=token,
    )


@bp.route("/share/<token>/download", methods=["POST"])
def share_download(token: str):
    """Download a shared file (requires invite code if set)."""
    datastore = get_datastore()
    share = datastore.get_drive_share_by_token(token)
    if not share:
        abort(404)

    if _share_expired(share):
        _log_share_event(datastore, share["id"], "download", "expired")
        flash("分享链接已过期", "error")
        return redirect(url_for("drive.share_page", token=token))

    if _share_limit_reached(share):
        _log_share_event(datastore, share["id"], "download", "limit_reached")
        flash("分享链接下载次数已用完", "error")
        return redirect(url_for("drive.share_page", token=token))

    if share.get("require_login") and not current_user.is_authenticated:
        _log_share_event(datastore, share["id"], "download", "login_required")
        flash("此分享仅允许登录用户下载", "error")
        return redirect(url_for("auth.login", next=url_for("drive.share_page", token=token)))

    if share["invite_code"]:
        provided = request.form.get("invite_code", "").strip()
        if provided != share["invite_code"]:
            _log_share_event(datastore, share["id"], "download", "invite_invalid")
            flash("邀请码错误", "error")
            return redirect(url_for("drive.share_page", token=token))

    file_record = datastore.get_drive_file(share["file_id"])
    if not file_record or file_record["is_folder"]:
        abort(404)

    user_dir = _user_drive_dir(file_record["username"])
    safe_file = secure_filename(file_record["filename"])
    if not safe_file:
        abort(404)

    pass

    datastore.increment_share_download_count(share["id"])
    _log_share_event(datastore, share["id"], "download", "success")

    return send_from_directory(
        str(user_dir), safe_file,
        as_attachment=True,
        download_name=file_record["original_name"],
    )


@bp.route("/share/<token>/qr.svg")
def share_qr(token: str):
    datastore = get_datastore()
    share = datastore.get_drive_share_by_token(token)
    if not share:
        abort(404)
    try:
        import qrcode
        from qrcode.image.svg import SvgPathImage
    except ImportError:
        abort(503)

    share_url = url_for("drive.share_page", token=token, _external=True)
    qr = qrcode.QRCode(border=2, box_size=8)
    qr.add_data(share_url)
    qr.make(fit=True)
    image = qr.make_image(image_factory=SvgPathImage)
    buf = BytesIO()
    image.save(buf)
    return Response(buf.getvalue(), mimetype="image/svg+xml")
