"""Image hosting (图床) blueprint — supports local, S3, and sm.ms backends."""
from __future__ import annotations

import hashlib
import logging
import os
import re
import secrets
import uuid
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import requests as http_requests
from flask import (
    Blueprint, abort, current_app, flash, jsonify, redirect,
    render_template, request, send_from_directory, url_for,
)
from flask_login import current_user, login_required
from werkzeug.utils import secure_filename

from .datastore import DataStore
from .security import path_is_within

bp = Blueprint("uploads", __name__, url_prefix="/uploads")
logger = logging.getLogger(__name__)

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp", "bmp"}
MAX_FILE_SIZE = 20 * 1024 * 1024  # 20 MB per file
ALLOWED_MIME_TYPES = {
    "image/png", "image/jpeg", "image/gif", "image/webp", "image/bmp",
}
# Extensions/MIME types that must NEVER be served inline (XSS risk).
_INLINE_DANGEROUS_EXTS = frozenset({"svg", "svgz", "ico", "html", "htm", "xml", "js"})


def get_datastore() -> DataStore:
    return current_app.extensions["datastore"]


def _uploads_dir() -> Path:
    base = Path(current_app.root_path).parent / "data" / "uploads"
    base.mkdir(parents=True, exist_ok=True)
    return base


def _user_dir(username: str) -> Path:
    safe = re.sub(r"[^a-zA-Z0-9_-]", "_", username)[:64]
    d = _uploads_dir() / safe
    d.mkdir(parents=True, exist_ok=True)
    return d


def _allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def _safe_unique_filename(original: str) -> str:
    ext = original.rsplit(".", 1)[1].lower() if "." in original else "png"
    return f"{secrets.token_hex(16)}.{ext}"


def _validate_image_header(data: bytes) -> bool:
    """Check magic bytes for common image formats to prevent fake uploads."""
    sigs = [
        b"\x89PNG",          # PNG
        b"\xff\xd8\xff",     # JPEG
        b"GIF87a", b"GIF89a",  # GIF
        b"RIFF",             # WEBP (RIFF container)
        b"<svg",             # SVG
        b"BM",               # BMP
        b"\x00\x00\x01\x00",  # ICO
    ]
    for sig in sigs:
        if data[:len(sig)] == sig:
            return True
    # SVG may start with BOM or whitespace
    stripped = data[:256].lstrip()
    if stripped.startswith(b"<?xml") or stripped.startswith(b"<svg"):
        return True
    return False


# ─── Storage backends ───

def _upload_local(username: str, file_data: bytes, filename: str) -> str:
    target = _user_dir(username) / filename
    target.write_bytes(file_data)
    return url_for("uploads.serve_image", username=username, filename=filename, _external=True)


def _upload_s3(username: str, file_data: bytes, filename: str, mime_type: str) -> str:
    try:
        import boto3
    except ImportError:
        raise RuntimeError("S3 上传需要安装 boto3：pip install boto3")

    endpoint = os.getenv("S3_ENDPOINT_URL", "")
    bucket = os.getenv("S3_BUCKET", "")
    access_key = os.getenv("S3_ACCESS_KEY", "")
    secret_key = os.getenv("S3_SECRET_KEY", "")
    region = os.getenv("S3_REGION", "us-east-1")

    if not (endpoint and bucket and access_key and secret_key):
        raise RuntimeError("S3 配置不完整，请设置 S3_ENDPOINT_URL, S3_BUCKET, S3_ACCESS_KEY, S3_SECRET_KEY")

    client = boto3.client(
        "s3",
        endpoint_url=endpoint,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=region,
    )
    key = f"uploads/{username}/{filename}"
    client.put_object(
        Bucket=bucket,
        Key=key,
        Body=file_data,
        ContentType=mime_type,
        ACL="public-read",
    )
    public_url = os.getenv("S3_PUBLIC_URL", endpoint)
    return f"{public_url.rstrip('/')}/{bucket}/{key}"


def _upload_smms(file_data: bytes, filename: str) -> str:
    api_token = os.getenv("SMMS_API_TOKEN", "")
    if not api_token:
        raise RuntimeError("sm.ms 上传需要设置 SMMS_API_TOKEN 环境变量")

    resp = http_requests.post(
        "https://sm.ms/api/v2/upload",
        headers={"Authorization": api_token},
        files={"smfile": (filename, file_data)},
        timeout=30,
    )
    data = resp.json()
    if data.get("success"):
        return data["data"]["url"]
    elif "images" in str(data.get("code", "")):
        return data.get("images", "")
    raise RuntimeError(f"sm.ms 上传失败: {data.get('message', '未知错误')}")


def _resolve_backend() -> str:
    """Return 'local', 's3', or 'smms' based on env config."""
    backend = os.getenv("IMAGE_STORAGE_BACKEND", "local").strip().lower()
    if backend in ("s3", "smms"):
        return backend
    return "local"


# ─── Routes ───

@bp.route("/")
@login_required
def index():
    datastore = get_datastore()
    uploads = datastore.list_uploads(current_user.username)
    quota = datastore.get_user_quota(current_user.username)
    used = datastore.get_user_used_space(current_user.username)
    return render_template(
        "uploads/index.html",
        uploads=uploads,
        quota=quota,
        used=used,
        backend=_resolve_backend(),
    )


@bp.route("/api/upload", methods=["POST"])
@login_required
def api_upload():
    datastore = get_datastore()

    if "file" not in request.files:
        return jsonify({"success": False, "message": "未选择文件"}), 400

    file = request.files["file"]
    if not file or not file.filename:
        return jsonify({"success": False, "message": "文件为空"}), 400

    # Fast-fail on Content-Length before reading into memory
    content_length = request.content_length
    if content_length and content_length > MAX_FILE_SIZE:
        return jsonify({"success": False, "message": f"文件过大，最大 {MAX_FILE_SIZE // 1024 // 1024} MB"}), 400

    original_name = secure_filename(file.filename) or "image.png"
    if not _allowed_file(original_name):
        return jsonify({"success": False, "message": "不支持的文件格式，仅支持 PNG / JPG / GIF / WebP / BMP"}), 400

    file_data = file.read()
    file_size = len(file_data)

    if file_size > MAX_FILE_SIZE:
        return jsonify({"success": False, "message": f"文件过大，最大 {MAX_FILE_SIZE // 1024 // 1024} MB"}), 400

    if file_size == 0:
        return jsonify({"success": False, "message": "文件内容为空"}), 400

    # Validate MIME type
    mime_type = file.content_type or "application/octet-stream"
    if mime_type not in ALLOWED_MIME_TYPES:
        return jsonify({"success": False, "message": "不支持的 MIME 类型"}), 400

    # Validate image magic bytes
    if not _validate_image_header(file_data):
        return jsonify({"success": False, "message": "文件内容不是有效的图片"}), 400

    # Pre-upload quota check
    if not datastore.check_quota(current_user.username, file_size):
        quota = datastore.get_user_quota(current_user.username)
        return jsonify({
            "success": False,
            "message": f"存储空间不足，配额 {quota / 1024 / 1024 / 1024:.1f} GB",
        }), 400

    safe_name = _safe_unique_filename(original_name)
    backend = _resolve_backend()

    try:
        if backend == "s3":
            storage_url = _upload_s3(current_user.username, file_data, safe_name, mime_type)
        elif backend == "smms":
            storage_url = _upload_smms(file_data, original_name)
        else:
            storage_url = _upload_local(current_user.username, file_data, safe_name)
    except Exception as exc:
        logger.exception("图片上传失败")
        if isinstance(exc, RuntimeError):
            return jsonify({"success": False, "message": "上传服务暂时不可用，请稍后再试或联系管理员"}), 503
        return jsonify({"success": False, "message": "上传失败，请稍后重试"}), 500

    record = datastore.add_upload(
        username=current_user.username,
        filename=safe_name,
        original_name=original_name,
        mime_type=mime_type,
        file_size=file_size,
        storage_type=backend,
        storage_url=storage_url,
    )

    return jsonify({
        "success": True,
        "data": {
            "id": record["id"],
            "url": storage_url,
            "original_name": original_name,
            "file_size": file_size,
            "markdown": f"![{original_name}]({storage_url})",
        },
    })


@bp.route("/api/delete/<upload_id>", methods=["POST"])
@login_required
def api_delete(upload_id: str):
    datastore = get_datastore()
    record = datastore.get_upload(upload_id)
    if not record:
        return jsonify({"success": False, "message": "未找到图片"}), 404
    if record["username"] != current_user.username and not current_user.is_admin:
        return jsonify({"success": False, "message": "无权删除"}), 403

    # Delete local file if applicable
    if record["storage_type"] == "local":
        try:
            from werkzeug.utils import safe_join
            safe_path = safe_join(str(_user_dir(record["username"])), record["filename"])
            if safe_path:
                path = Path(safe_path)
                if path.exists():
                    path.unlink()
        except OSError:
            logger.warning("删除本地文件失败: %s", record["filename"])

    datastore.delete_upload(upload_id)
    return jsonify({"success": True})


@bp.route("/image/<username>/<filename>")
def serve_image(username: str, filename: str):
    safe_user = re.sub(r"[^a-zA-Z0-9_-]", "_", username)[:64]
    safe_file = secure_filename(filename)
    if not safe_file:
        abort(404)
    directory = _uploads_dir() / safe_user
    if not directory.exists():
        abort(404)

    ext = safe_file.rsplit(".", 1)[-1].lower() if "." in safe_file else ""
    # Force download (attachment) for any type that could execute inline in browser
    from flask import make_response
    try:
        resp = make_response(send_from_directory(str(directory), safe_file))
    except Exception:
        abort(404)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    if ext in _INLINE_DANGEROUS_EXTS:
        resp.headers["Content-Disposition"] = f'attachment; filename="{safe_file}"'
    return resp
