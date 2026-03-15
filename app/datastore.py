from __future__ import annotations

import json
import logging
import os
import secrets
import sqlite3
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from threading import RLock, local
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Literal, Tuple, cast

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from .oj_client import (
    OJAccountNotFound,
    OJGroup,
    OJGroupMember,
    OJInvalidCredentials,
    OJLoginError,
    OJServiceUnavailable,
    OJUserInfo,
    OnlineJudgeClient,
)


ISO_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
DEFAULT_CATEGORY_TAG = "未分类"
DEFAULT_CLASS_TAG = "未分班"


def utcnow_str() -> str:
    return datetime.now(timezone.utc).strftime(ISO_FORMAT)


def _stable_node_id(prefix: str, value: str) -> str:
    seed = f"{prefix}:{value}"
    return f"{prefix}-{uuid.uuid5(uuid.NAMESPACE_DNS, seed).hex[:12]}"


MessagePreference = Literal["notify", "silent", "block"]
MESSAGE_PREFERENCE_DEFAULT: MessagePreference = "notify"
MESSAGE_PREFERENCES: Set[MessagePreference] = {"notify", "silent", "block"}


logger = logging.getLogger(__name__)

CLASS_SYNC_INTERVAL = timedelta(minutes=5)
CLASS_SYNC_LOCK_STALE = timedelta(minutes=10)
SYSTEM_USERNAME = "SYSTEM"


class SQLiteConnectionManager:
    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._local = local()

    def get_connection(self) -> sqlite3.Connection:
        conn = getattr(self._local, "connection", None)
        if conn is None:
            conn = sqlite3.connect(
                self.db_path,
                detect_types=sqlite3.PARSE_DECLTYPES,
                check_same_thread=False,
            )
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA temp_store=MEMORY")
            conn.execute("PRAGMA cache_size=-8000")
            conn.execute("PRAGMA busy_timeout=5000")
            self._local.connection = conn
        return conn

    def close_connection(self) -> None:
        conn = getattr(self._local, "connection", None)
        if conn is not None:
            conn.close()
            self._local.connection = None


@dataclass
class User(UserMixin):
    username: str
    password_hash: str
    role: str = "user"
    real_name: str = ""
    is_banned: bool = False

    def get_id(self) -> str:  # type: ignore[override]
        return self.username

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    def is_active(self) -> bool:  # type: ignore[override]
        return not self.is_banned

    def to_record(self) -> Dict[str, Any]:
        return {
            "username": self.username,
            "password_hash": self.password_hash,
            "role": self.role,
            "real_name": self.real_name,
            "is_banned": self.is_banned,
        }


class DataStore:
    def __init__(self, base_path: Path):
        self.base_path = base_path
        self.base_path.mkdir(parents=True, exist_ok=True)
        self.db_path = self.base_path / "forum.sqlite3"
        self._connection_manager = SQLiteConnectionManager(self.db_path)
        self._setup_lock = RLock()
        self._setup_complete = False
        self._setup_database()
        self._oj_client = OnlineJudgeClient()

    def _get_metadata_value(self, key: str) -> Optional[str]:
        conn = self._conn()
        row = conn.execute("SELECT value FROM metadata WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None

    def _set_metadata_value(self, key: str, value: str) -> None:
        conn = self._conn()
        with conn:
            conn.execute(
                "INSERT INTO metadata (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )

    @staticmethod
    def _parse_timestamp(value: Optional[str]) -> Optional[datetime]:
        if not value:
            return None
        try:
            return datetime.strptime(value, ISO_FORMAT)
        except ValueError:
            return None

    def _try_acquire_class_sync_lock(self, now: datetime) -> bool:
        conn = self._conn()
        lock_key = "class_sync_lock"
        last_run_key = "class_sync_last_run"
        with conn:
            last_run_row = conn.execute(
                "SELECT value FROM metadata WHERE key = ?",
                (last_run_key,),
            ).fetchone()
            last_run = self._parse_timestamp(last_run_row["value"] if last_run_row else None)
            if last_run and now - last_run < CLASS_SYNC_INTERVAL:
                logger.debug("跳过班级同步：上次同步距今不足 %s", CLASS_SYNC_INTERVAL)
                return False

            lock_row = conn.execute(
                "SELECT value FROM metadata WHERE key = ?",
                (lock_key,),
            ).fetchone()
            lock_timestamp = self._parse_timestamp(lock_row["value"] if lock_row else None)
            if lock_timestamp and now - lock_timestamp < CLASS_SYNC_LOCK_STALE:
                logger.debug("跳过班级同步：已有进行中的同步任务（%s 前启动）", lock_timestamp)
                return False

            conn.execute(
                "INSERT INTO metadata (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (lock_key, now.strftime(ISO_FORMAT)),
            )
            return True

    def _release_class_sync_lock(self) -> None:
        conn = self._conn()
        with conn:
            conn.execute("DELETE FROM metadata WHERE key = ?", ("class_sync_lock",))

    def _conn(self) -> sqlite3.Connection:
        return self._connection_manager.get_connection()

    @staticmethod
    def _escape_like(term: str) -> str:
        return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")

    def _setup_database(self) -> None:
        if self._setup_complete:
            return
        with self._setup_lock:
            if self._setup_complete:
                return
            conn = self._conn()
            self._ensure_schema(conn)
            self._maybe_migrate_legacy(conn)
            self._ensure_tag_defaults(conn)
            self._migrate_post_tag_columns(conn)
            self._bootstrap_admin(conn)
            self._ensure_system_user(conn)
            self._setup_complete = True

    @staticmethod
    def _ensure_schema(conn: sqlite3.Connection) -> None:
        with conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL,
                    real_name TEXT NOT NULL,
                    is_banned INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS posts (
                    id TEXT PRIMARY KEY,
                    author TEXT NOT NULL,
                    title TEXT NOT NULL,
                    content TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    category_tag TEXT NOT NULL DEFAULT '',
                    class_tag TEXT NOT NULL DEFAULT '',
                    is_hidden INTEGER NOT NULL DEFAULT 0,
                    FOREIGN KEY(author) REFERENCES users(username) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_posts_author ON posts(author);
                CREATE INDEX IF NOT EXISTS idx_posts_created_at ON posts(created_at);
                CREATE INDEX IF NOT EXISTS idx_posts_category ON posts(category_tag);
                CREATE INDEX IF NOT EXISTS idx_posts_class ON posts(class_tag);

                CREATE TABLE IF NOT EXISTS post_tags (
                    post_id TEXT NOT NULL,
                    tag TEXT NOT NULL,
                    PRIMARY KEY (post_id, tag),
                    FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_post_tags_tag ON post_tags(tag);

                CREATE TABLE IF NOT EXISTS comments (
                    id TEXT PRIMARY KEY,
                    post_id TEXT NOT NULL,
                    author TEXT NOT NULL,
                    content TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE,
                    FOREIGN KEY(author) REFERENCES users(username) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_comments_post ON comments(post_id);

                CREATE TABLE IF NOT EXISTS normal_tags (
                    name TEXT PRIMARY KEY,
                    is_column INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS post_favorites (
                    post_id TEXT NOT NULL,
                    username TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (post_id, username),
                    FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE,
                    FOREIGN KEY(username) REFERENCES users(username) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_post_favorites_user ON post_favorites(username);
                CREATE INDEX IF NOT EXISTS idx_post_favorites_post ON post_favorites(post_id);

                CREATE TABLE IF NOT EXISTS class_tags (
                    name TEXT PRIMARY KEY,
                    source TEXT NOT NULL DEFAULT 'manual',
                    external_id TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_class_tags_source ON class_tags(source);
                CREATE UNIQUE INDEX IF NOT EXISTS idx_class_tags_external ON class_tags(external_id) WHERE external_id IS NOT NULL;

                CREATE TABLE IF NOT EXISTS class_groups (
                    tag TEXT PRIMARY KEY,
                    display_name TEXT NOT NULL,
                    last_synced_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS class_memberships (
                    class_tag TEXT NOT NULL,
                    username TEXT NOT NULL,
                    real_name TEXT,
                    PRIMARY KEY (class_tag, username),
                    FOREIGN KEY(class_tag) REFERENCES class_groups(tag) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_class_memberships_user ON class_memberships(username);

                CREATE TABLE IF NOT EXISTS private_messages (
                    id TEXT PRIMARY KEY,
                    sender TEXT NOT NULL,
                    recipient TEXT NOT NULL,
                    content TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    is_read INTEGER NOT NULL DEFAULT 0,
                    is_system INTEGER NOT NULL DEFAULT 0,
                    FOREIGN KEY(sender) REFERENCES users(username) ON DELETE CASCADE,
                    FOREIGN KEY(recipient) REFERENCES users(username) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_private_messages_recipient_created
                    ON private_messages(recipient, created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_private_messages_sender_created
                    ON private_messages(sender, created_at DESC);

                CREATE TABLE IF NOT EXISTS user_uploads (
                    id TEXT PRIMARY KEY,
                    username TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    original_name TEXT NOT NULL,
                    mime_type TEXT NOT NULL,
                    file_size INTEGER NOT NULL,
                    storage_type TEXT NOT NULL DEFAULT 'local',
                    storage_url TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(username) REFERENCES users(username) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_user_uploads_user ON user_uploads(username);

                CREATE TABLE IF NOT EXISTS user_quotas (
                    username TEXT PRIMARY KEY,
                    quota_bytes INTEGER NOT NULL DEFAULT 10737418240,
                    FOREIGN KEY(username) REFERENCES users(username) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS drive_files (
                    id TEXT PRIMARY KEY,
                    username TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    original_name TEXT NOT NULL,
                    mime_type TEXT NOT NULL,
                    file_size INTEGER NOT NULL,
                    parent_id TEXT,
                    is_folder INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(username) REFERENCES users(username) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_drive_files_user ON drive_files(username);
                CREATE INDEX IF NOT EXISTS idx_drive_files_parent ON drive_files(parent_id);

                CREATE TABLE IF NOT EXISTS drive_shares (
                    id TEXT PRIMARY KEY,
                    file_id TEXT NOT NULL,
                    owner_username TEXT NOT NULL,
                    share_token TEXT NOT NULL UNIQUE,
                    invite_code TEXT,
                    expires_at TEXT,
                    max_downloads INTEGER,
                    require_login INTEGER NOT NULL DEFAULT 0,
                    download_count INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(file_id) REFERENCES drive_files(id) ON DELETE CASCADE,
                    FOREIGN KEY(owner_username) REFERENCES users(username) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_drive_shares_token ON drive_shares(share_token);
                CREATE INDEX IF NOT EXISTS idx_drive_shares_file ON drive_shares(file_id);

                CREATE TABLE IF NOT EXISTS drive_share_access_logs (
                    id TEXT PRIMARY KEY,
                    share_id TEXT NOT NULL,
                    access_type TEXT NOT NULL,
                    access_status TEXT NOT NULL,
                    username TEXT,
                    ip_address TEXT,
                    user_agent TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(share_id) REFERENCES drive_shares(id) ON DELETE CASCADE,
                    FOREIGN KEY(username) REFERENCES users(username) ON DELETE SET NULL
                );

                CREATE INDEX IF NOT EXISTS idx_drive_share_logs_share ON drive_share_access_logs(share_id);
                CREATE INDEX IF NOT EXISTS idx_drive_share_logs_created ON drive_share_access_logs(created_at);

                CREATE TABLE IF NOT EXISTS user_preferences (
                    username TEXT PRIMARY KEY,
                    theme TEXT NOT NULL DEFAULT 'light',
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(username) REFERENCES users(username) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS feedback (
                    id TEXT PRIMARY KEY,
                    username TEXT NOT NULL,
                    content TEXT NOT NULL,
                    category TEXT NOT NULL DEFAULT 'general',
                    status TEXT NOT NULL DEFAULT 'pending',
                    created_at TEXT NOT NULL,
                    admin_reply TEXT,
                    replied_at TEXT,
                    FOREIGN KEY(username) REFERENCES users(username) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_feedback_user ON feedback(username);
                CREATE INDEX IF NOT EXISTS idx_feedback_status ON feedback(status);

                CREATE TABLE IF NOT EXISTS message_preferences (
                    owner TEXT NOT NULL,
                    other_user TEXT NOT NULL,
                    preference TEXT NOT NULL CHECK (preference IN ('notify','silent','block')),
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (owner, other_user),
                    FOREIGN KEY(owner) REFERENCES users(username) ON DELETE CASCADE,
                    FOREIGN KEY(other_user) REFERENCES users(username) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS user_labels (
                    id TEXT PRIMARY KEY,
                    username TEXT NOT NULL,
                    label TEXT NOT NULL,
                    color TEXT NOT NULL DEFAULT 'blue',
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(username) REFERENCES users(username) ON DELETE CASCADE
                );
                CREATE UNIQUE INDEX IF NOT EXISTS idx_user_labels_unique ON user_labels(username, label);
                """
            )
            columns = {
                row["name"]
                for row in conn.execute("PRAGMA table_info(users)")
            }
            if "constant_tags" in columns:
                has_is_banned = "is_banned" in columns
                # Migration: drop legacy constant_tags column while preserving is_banned values
                is_banned_expr = "COALESCE(is_banned, 0)" if has_is_banned else "0"
                migration_sql = "\n".join(
                    [
                        "PRAGMA foreign_keys=OFF;",
                        "ALTER TABLE users RENAME TO users_old;",
                        "CREATE TABLE users (",
                        "    username TEXT PRIMARY KEY,",
                        "    password_hash TEXT NOT NULL,",
                        "    role TEXT NOT NULL,",
                        "    real_name TEXT NOT NULL,",
                        "    is_banned INTEGER NOT NULL DEFAULT 0",
                        ");",
                        "INSERT INTO users (username, password_hash, role, real_name, is_banned)",
                        "SELECT username, password_hash, role, real_name, " + is_banned_expr + " FROM users_old;",
                        "DROP TABLE users_old;",
                        "PRAGMA foreign_keys=ON;",
                    ]
                )
                conn.executescript(migration_sql)
                columns = {
                    row["name"]
                    for row in conn.execute("PRAGMA table_info(users)")
                }
            if "is_banned" not in columns:
                conn.execute("ALTER TABLE users ADD COLUMN is_banned INTEGER NOT NULL DEFAULT 0")

            normal_tag_columns = {
                row["name"]
                for row in conn.execute("PRAGMA table_info(normal_tags)")
            }
            if "is_column" not in normal_tag_columns:
                conn.execute("ALTER TABLE normal_tags ADD COLUMN is_column INTEGER NOT NULL DEFAULT 0")
            post_columns = {
                row["name"]
                for row in conn.execute("PRAGMA table_info(posts)")
            }
            if "category_tag" not in post_columns:
                conn.execute("ALTER TABLE posts ADD COLUMN category_tag TEXT NOT NULL DEFAULT ''")
            if "class_tag" not in post_columns:
                conn.execute("ALTER TABLE posts ADD COLUMN class_tag TEXT NOT NULL DEFAULT ''")
            if "is_hidden" not in post_columns:
                conn.execute("ALTER TABLE posts ADD COLUMN is_hidden INTEGER NOT NULL DEFAULT 0")
            post_columns = {
                row["name"]
                for row in conn.execute("PRAGMA table_info(posts)")
            }
            if "is_hidden" in post_columns:
                conn.execute("CREATE INDEX IF NOT EXISTS idx_posts_hidden ON posts(is_hidden)")
            post_columns = {
                row["name"]
                for row in conn.execute("PRAGMA table_info(posts)")
            }
            if "is_pinned" not in post_columns:
                conn.execute("ALTER TABLE posts ADD COLUMN is_pinned INTEGER NOT NULL DEFAULT 0")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_posts_pinned ON posts(is_pinned)")

            drive_share_columns = {
                row["name"]
                for row in conn.execute("PRAGMA table_info(drive_shares)")
            }
            if "max_downloads" not in drive_share_columns:
                conn.execute("ALTER TABLE drive_shares ADD COLUMN max_downloads INTEGER")
            if "require_login" not in drive_share_columns:
                conn.execute("ALTER TABLE drive_shares ADD COLUMN require_login INTEGER NOT NULL DEFAULT 0")

            conn.execute("DROP TABLE IF EXISTS constant_tags")
            conn.execute("DROP TABLE IF EXISTS tag_nodes")

    def _maybe_migrate_legacy(self, conn: sqlite3.Connection) -> None:
        sentinel = self.base_path / ".sqlite_migrated"
        if sentinel.exists():
            return
        legacy_sources = [
            self.base_path / "users.json",
            self.base_path / "tags.json",
            self.base_path / "tag_tree.json",
            self.base_path / "posts.json",
            self.base_path / "posts",
        ]
        if not any(path.exists() for path in legacy_sources):
            return
        has_users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        has_posts = conn.execute("SELECT COUNT(*) FROM posts").fetchone()[0]
        if has_users or has_posts:
            return
        legacy = self._load_legacy_payload()
        if not any(legacy.values()):
            return
        with conn:
            for user in legacy.get("users", []):
                conn.execute(
                    "INSERT OR IGNORE INTO users (username, password_hash, role, real_name) VALUES (?, ?, ?, ?)",
                    (
                        user.get("username"),
                        user.get("password_hash"),
                        user.get("role", "user"),
                        user.get("real_name", ""),
                    ),
                )
            for tag in legacy.get("normal_tags", []):
                conn.execute(
                    "INSERT OR IGNORE INTO normal_tags (name) VALUES (?)",
                    (tag,),
                )
            for post in legacy.get("posts", []):
                conn.execute(
                    "INSERT OR IGNORE INTO posts (id, author, title, content, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        post["id"],
                        post.get("author", ""),
                        post.get("title", ""),
                        post.get("content", ""),
                        post.get("created_at", utcnow_str()),
                        post.get("updated_at", post.get("created_at", utcnow_str())),
                    ),
                )
                tags = post.get("tags", [])
                for tag in tags:
                    conn.execute(
                        "INSERT OR IGNORE INTO post_tags (post_id, tag) VALUES (?, ?)",
                        (post["id"], tag),
                    )
                for comment in post.get("comments", []):
                    conn.execute(
                        "INSERT OR IGNORE INTO comments (id, post_id, author, content, created_at) VALUES (?, ?, ?, ?, ?)",
                        (
                            comment["id"],
                            post["id"],
                            comment.get("author", ""),
                            comment.get("content", ""),
                            comment.get("created_at", utcnow_str()),
                        ),
                    )
        try:
            sentinel.touch(exist_ok=True)
        except OSError:
            pass

    def _load_legacy_payload(self) -> Dict[str, Any]:
        return {
            "users": self._load_legacy_users(),
            "normal_tags": self._load_legacy_normal_tags(),
            "tag_tree": self._load_legacy_tag_tree(),
            "posts": self._load_legacy_posts(),
        }

    def _load_legacy_users(self) -> List[Dict[str, Any]]:
        users_path = self.base_path / "users.json"
        if not users_path.exists():
            return []
        try:
            raw = json.loads(users_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []
        result: List[Dict[str, Any]] = []
        for item in raw if isinstance(raw, list) else []:
            if not isinstance(item, dict) or "username" not in item or "password_hash" not in item:
                continue
            item.setdefault("role", "user")
            item.setdefault("real_name", "")
            result.append(item)
        return result

    def _load_legacy_normal_tags(self) -> List[str]:
        tags_path = self.base_path / "tags.json"
        if not tags_path.exists():
            return []
        try:
            payload = json.loads(tags_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []
        normal_tags = payload.get("normal_tags") if isinstance(payload, dict) else []
        if not isinstance(normal_tags, list):
            return []
        return sorted({str(tag) for tag in normal_tags if isinstance(tag, str) and tag})

    def _load_legacy_tag_tree(self) -> Dict[str, Any]:
        tree_path = self.base_path / "tag_tree.json"
        if not tree_path.exists():
            return {}
        try:
            payload = json.loads(tree_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        nodes = payload.get("nodes") if isinstance(payload, dict) else []
        if not isinstance(nodes, list):
            return {}
        sanitized: List[Dict[str, Any]] = []
        for node in nodes:
            if not isinstance(node, dict) or "id" not in node:
                continue
            sanitized.append(
                {
                    "id": node["id"],
                    "tag": node.get("tag"),
                    "children": [child for child in node.get("children", []) if isinstance(child, str)],
                }
            )
        return {"nodes": sanitized}

    def _load_legacy_posts(self) -> List[Dict[str, Any]]:
        posts: Dict[str, Dict[str, Any]] = {}
        legacy_file = self.base_path / "posts.json"
        if legacy_file.exists():
            try:
                raw_posts = json.loads(legacy_file.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                raw_posts = []
            for post in raw_posts if isinstance(raw_posts, list) else []:
                if isinstance(post, dict) and post.get("id"):
                    posts[post["id"]] = post
        posts_dir = self.base_path / "posts"
        if posts_dir.exists():
            for path in posts_dir.glob("*.json"):
                try:
                    data = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    continue
                if isinstance(data, dict) and data.get("id"):
                    posts[data["id"]] = data
        sanitized: List[Dict[str, Any]] = []
        for post in posts.values():
            post_id = post.get("id")
            if not isinstance(post_id, str):
                continue
            title = str(post.get("title", ""))
            content = str(post.get("content", ""))
            author = str(post.get("author", ""))
            tags = sorted({tag for tag in post.get("tags", []) if isinstance(tag, str) and tag})
            created_at = post.get("created_at") or utcnow_str()
            updated_at = post.get("updated_at") or created_at
            comments_raw = post.get("comments")
            if not isinstance(comments_raw, list):
                comments_raw = []
            comments: List[Dict[str, Any]] = []
            for comment in comments_raw:
                if not isinstance(comment, dict):
                    continue
                comment_id = comment.get("id") or uuid.uuid4().hex
                comments.append(
                    {
                        "id": comment_id,
                        "author": str(comment.get("author", "")),
                        "content": str(comment.get("content", "")),
                        "created_at": comment.get("created_at") or utcnow_str(),
                    }
                )
            sanitized.append(
                {
                    "id": post_id,
                    "author": author,
                    "title": title,
                    "content": content,
                    "tags": tags,
                    "created_at": created_at,
                    "updated_at": updated_at,
                    "comments": comments,
                }
            )
        return sanitized

    def _bootstrap_admin(self, conn: sqlite3.Connection) -> None:
        with conn:
            count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            if count == 0:
                default_password = os.getenv("ADMIN_DEFAULT_PASSWORD")
                generated = False
                if not default_password:
                    generated = True
                    default_password = secrets.token_urlsafe(16)
                password_hash = generate_password_hash(default_password)
                conn.execute(
                    "INSERT INTO users (username, password_hash, role, real_name) VALUES (?, ?, ?, ?)",
                    ("admin", password_hash, "admin", ""),
                )
                if generated:
                    password_file = self.base_path / "admin_initial_password.txt"
                    try:
                        password_file.write_text(
                            "初始化管理员账号已创建，用户名：admin\n临时密码：%s\n请尽快登录并修改部署配置。\n" % default_password,
                            encoding="utf-8",
                        )
                    except OSError:
                        logger.fatal("初始化管理员账号已创建，但写入初始密码文件失败，请改用环境变量 ADMIN_DEFAULT_PASSWORD 重新部署。")
                    else:
                        logger.warning("初始化管理员账号已创建，临时密码已写入 %s，请妥善保存并及时删除。", password_file)
                else:
                    logger.info("初始化管理员账号已创建，用户名 admin，使用环境变量指定密码")

    @staticmethod
    def _ensure_system_user(conn: sqlite3.Connection) -> None:
        with conn:
            row = conn.execute(
                "SELECT role FROM users WHERE username = ?",
                (SYSTEM_USERNAME,),
            ).fetchone()
            if row:
                conn.execute(
                    "UPDATE users SET role = 'system', is_banned = 1 WHERE username = ?",
                    (SYSTEM_USERNAME,),
                )
                return
            placeholder_password = generate_password_hash(uuid.uuid4().hex)
            conn.execute(
                """
                INSERT INTO users (username, password_hash, role, real_name, is_banned)
                VALUES (?, ?, 'system', '', 1)
                """,
                (SYSTEM_USERNAME, placeholder_password),
            )

    # Public API methods --------------------------------------------------

    def list_users(self) -> List[Dict[str, Any]]:
        conn = self._conn()
        rows = conn.execute(
            "SELECT username, password_hash, role, real_name, is_banned FROM users"
        ).fetchall()
        users: List[Dict[str, Any]] = []
        for row in rows:
            if row["username"] == SYSTEM_USERNAME:
                continue
            users.append(
                {
                    "username": row["username"],
                    "password_hash": row["password_hash"],
                    "role": row["role"],
                    "real_name": row["real_name"],
                    "is_banned": bool(row["is_banned"]),
                }
            )
        return users

    def search_users(self, keyword: str, limit: int = 20) -> List[Dict[str, Any]]:
        term = keyword.strip()
        if not term:
            return []
        conn = self._conn()
        escaped = self._escape_like(term)
        pattern = f"%{escaped}%"
        capped_limit = max(1, min(limit, 50))
        rows = conn.execute(
            """
            SELECT username, real_name
            FROM users
            WHERE username LIKE ? ESCAPE '\\'
            ORDER BY username
            LIMIT ?
            """,
            (pattern, capped_limit),
        ).fetchall()
        results: List[Dict[str, Any]] = []
        for row in rows:
            if row["username"] == SYSTEM_USERNAME:
                continue
            results.append(
                {
                    "username": row["username"],
                    "real_name": row["real_name"],
                }
            )
        return results

    def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        conn = self._conn()
        row = conn.execute(
            "SELECT username, password_hash, role, real_name, is_banned FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        if not row:
            return None
        return {
            "username": row["username"],
            "password_hash": row["password_hash"],
            "role": row["role"],
            "real_name": row["real_name"],
            "is_banned": bool(row["is_banned"]),
        }

    def load_user(self, username: str) -> Optional[User]:
        record = self.get_user(username)
        if not record:
            return None
        return User(
            username=record["username"],
            password_hash=record["password_hash"],
            role=record.get("role", "user"),
            real_name=record.get("real_name", ""),
            is_banned=bool(record.get("is_banned", False)),
        )

    def create_user(
        self,
        username: str,
        password: str,
        role: str = "user",
        real_name: str = "",
    ) -> User:
        if self.get_user(username):
            raise ValueError("用户已存在")
        conn = self._conn()
        password_hash = generate_password_hash(password)
        with conn:
            conn.execute(
                "INSERT INTO users (username, password_hash, role, real_name) VALUES (?, ?, ?, ?)",
                (
                    username,
                    password_hash,
                    role,
                    real_name.strip(),
                ),
            )
        return User(
            username=username,
            password_hash=password_hash,
            role=role,
            real_name=real_name.strip(),
            is_banned=False,
        )

    def set_user_role(self, username: str, role: str) -> None:
        conn = self._conn()
        with conn:
            updated = conn.execute(
                "UPDATE users SET role = ? WHERE username = ?",
                (role, username),
            )
            if updated.rowcount == 0:
                raise ValueError("未找到用户")

    def set_user_banned(self, username: str, banned: bool) -> None:
        conn = self._conn()
        with conn:
            updated = conn.execute(
                "UPDATE users SET is_banned = ? WHERE username = ?",
                (1 if banned else 0, username),
            )
            if updated.rowcount == 0:
                raise ValueError("未找到用户")

    def update_user_real_name(self, username: str, real_name: str) -> None:
        conn = self._conn()
        with conn:
            updated = conn.execute(
                "UPDATE users SET real_name = ? WHERE username = ?",
                (real_name.strip(), username),
            )
            if updated.rowcount == 0:
                raise ValueError("未找到用户")

    def verify_user(self, username: str, password: str) -> Optional[User]:
        if self._oj_client:
            try:
                remote_user = self._oj_client.authenticate(username, password)
            except OJInvalidCredentials:
                return None
            except (OJAccountNotFound, OJServiceUnavailable):
                pass
            else:
                return self._upsert_remote_user(remote_user, password)
        return self._verify_local_credentials(username, password)

    def verify_user_with_cookie(self, username: str, phpsessid: str) -> Optional[User]:
        if not phpsessid:
            return None
        if self._oj_client:
            try:
                remote_user = self._oj_client.authenticate_with_cookie(username, phpsessid)
            except OJInvalidCredentials:
                return None
            except (OJAccountNotFound, OJServiceUnavailable):
                return None
            else:
                return self._upsert_remote_user_cookie(remote_user)
        return None

    def resolve_username_from_cookie(self, phpsessid: str) -> Optional[str]:
        if not phpsessid:
            return None
        if not self._oj_client:
            return None
        try:
            return self._oj_client.resolve_username_from_cookie(phpsessid)
        except OJLoginError:
            return None

    def _verify_local_credentials(self, username: str, password: str) -> Optional[User]:
        record = self.get_user(username)
        if not record:
            return None
        if not check_password_hash(record["password_hash"], password):
            return None
        return User(
            username=record["username"],
            password_hash=record["password_hash"],
            role=record.get("role", "user"),
            real_name=record.get("real_name", ""),
            is_banned=bool(record.get("is_banned", False)),
        )

    def _upsert_remote_user(self, remote_user: OJUserInfo, password: str) -> User:
        conn = self._conn()
        password_hash = generate_password_hash(password)
        with conn:
            existing = conn.execute(
                "SELECT username, role, real_name, is_banned FROM users WHERE username = ?",
                (remote_user.username,),
            ).fetchone()
            if existing:
                conn.execute(
                    "UPDATE users SET password_hash = ?, real_name = ? WHERE username = ?",
                    (password_hash, remote_user.real_name, remote_user.username),
                )
                role = existing["role"]
                is_banned = bool(existing["is_banned"])
            else:
                conn.execute(
                    "INSERT INTO users (username, password_hash, role, real_name) VALUES (?, ?, ?, ?)",
                    (
                        remote_user.username,
                        password_hash,
                        "user",
                        remote_user.real_name,
                    ),
                )
                role = "user"
                is_banned = False
        return User(
            username=remote_user.username,
            password_hash=password_hash,
            role=role,
            real_name=remote_user.real_name,
            is_banned=is_banned,
        )

    def _upsert_remote_user_cookie(self, remote_user: OJUserInfo) -> User:
        conn = self._conn()
        password_hash = generate_password_hash(secrets.token_hex(16))
        with conn:
            existing = conn.execute(
                "SELECT username, role, real_name, is_banned, password_hash FROM users WHERE username = ?",
                (remote_user.username,),
            ).fetchone()
            if existing:
                password_hash = existing["password_hash"] or password_hash
                conn.execute(
                    "UPDATE users SET real_name = ? WHERE username = ?",
                    (remote_user.real_name, remote_user.username),
                )
                role = existing["role"]
                is_banned = bool(existing["is_banned"])
            else:
                conn.execute(
                    "INSERT INTO users (username, password_hash, role, real_name) VALUES (?, ?, ?, ?)",
                    (
                        remote_user.username,
                        password_hash,
                        "user",
                        remote_user.real_name,
                    ),
                )
                role = "user"
                is_banned = False
        return User(
            username=remote_user.username,
            password_hash=password_hash,
            role=role,
            real_name=remote_user.real_name,
            is_banned=is_banned,
        )

    # Posts ------------------------------------------------------------

    def list_posts(self) -> List[Dict[str, Any]]:
        conn = self._conn()
        rows = conn.execute(
            """
            SELECT id, author, title, content, created_at, updated_at, category_tag, class_tag, is_hidden, is_pinned
            FROM posts
            ORDER BY is_pinned DESC, created_at DESC
            """
        ).fetchall()
        return self._build_posts_from_rows(rows)

    def list_posts_filtered(
        self,
        *,
        category_tag: Optional[str] = None,
        class_tags: Optional[Iterable[str]] = None,
    ) -> List[Dict[str, Any]]:
        conn = self._conn()
        clauses: List[str] = []
        params: List[Any] = []
        if category_tag:
            clauses.append("category_tag = ?")
            params.append(category_tag.strip())
        class_tag_values = [tag.strip() for tag in class_tags or [] if tag and tag.strip()]
        if class_tag_values:
            placeholders = ",".join(["?"] * len(class_tag_values))
            clauses.append(f"class_tag IN ({placeholders})")
            params.extend(class_tag_values)
        where = ""
        if clauses:
            where = "WHERE " + " AND ".join(clauses)
        rows = conn.execute(
            f"""
            SELECT id, author, title, content, created_at, updated_at, category_tag, class_tag, is_hidden, is_pinned
            FROM posts
            {where}
            ORDER BY is_pinned DESC, created_at DESC
            """,
            params,
        ).fetchall()
        return self._build_posts_from_rows(rows)

    def get_post(self, post_id: str) -> Optional[Dict[str, Any]]:
        conn = self._conn()
        row = conn.execute(
            """
            SELECT id, author, title, content, created_at, updated_at, category_tag, class_tag, is_hidden, is_pinned
            FROM posts
            WHERE id = ?
            """,
            (post_id,),
        ).fetchone()
        if not row:
            return None
        return self._build_posts_from_rows([row])[0]

    def create_post(
        self,
        author: str,
        title: str,
        content: str,
        *,
        category_tag: str,
        class_tag: str,
        is_hidden: bool = False,
    ) -> Dict[str, Any]:
        conn = self._conn()
        post_id = uuid.uuid4().hex
        timestamp = utcnow_str()
        category = (category_tag or DEFAULT_CATEGORY_TAG).strip() or DEFAULT_CATEGORY_TAG
        class_value = (class_tag or DEFAULT_CLASS_TAG).strip() or DEFAULT_CLASS_TAG
        all_tags = [category, class_value]
        normalized_tags = self._normalize_tags(all_tags)
        with conn:
            conn.execute(
                """
                INSERT INTO posts (id, author, title, content, created_at, updated_at, category_tag, class_tag, is_hidden)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (post_id, author, title, content, timestamp, timestamp, category, class_value, 1 if is_hidden else 0),
            )
            self._ensure_category_exists(conn, category)
            self._ensure_class_exists(conn, class_value)
            self._replace_post_tags(conn, post_id, normalized_tags)
        return self.get_post(post_id) or {
            "id": post_id,
            "author": author,
            "title": title,
            "content": content,
            "category_tag": category,
            "class_tag": class_value,
            "tags": normalized_tags,
            "created_at": timestamp,
            "updated_at": timestamp,
            "comments": [],
            "is_hidden": bool(is_hidden),
        }

    def update_post(
        self,
        post_id: str,
        *,
        title: Optional[str] = None,
        content: Optional[str] = None,
        category_tag: Optional[str] = None,
        class_tag: Optional[str] = None,
        is_hidden: Optional[bool] = None,
    ) -> Dict[str, Any]:
        conn = self._conn()
        existing = self.get_post(post_id)
        if existing is None:
            raise ValueError("未找到文章")

        current_category = (existing.get("category_tag") or DEFAULT_CATEGORY_TAG).strip() or DEFAULT_CATEGORY_TAG
        current_class = (existing.get("class_tag") or DEFAULT_CLASS_TAG).strip() or DEFAULT_CLASS_TAG
        new_category = (
            (category_tag or current_category).strip() or DEFAULT_CATEGORY_TAG
            if category_tag is not None
            else current_category
        )
        new_class = (
            (class_tag or current_class).strip() or DEFAULT_CLASS_TAG
            if class_tag is not None
            else current_class
        )
        updates: List[str] = []
        params: List[Any] = []
        if title is not None:
            updates.append("title = ?")
            params.append(title)
        if content is not None:
            updates.append("content = ?")
            params.append(content)
        if category_tag is not None:
            updates.append("category_tag = ?")
            params.append(new_category)
        if class_tag is not None:
            updates.append("class_tag = ?")
            params.append(new_class)
        if is_hidden is not None:
            updates.append("is_hidden = ?")
            params.append(1 if is_hidden else 0)
        should_update_tags = category_tag is not None or class_tag is not None
        should_touch = bool(updates) or should_update_tags
        if should_touch:
            updates.append("updated_at = ?")
            params.append(utcnow_str())
        params.append(post_id)
        with conn:
            self._ensure_category_exists(conn, new_category)
            self._ensure_class_exists(conn, new_class)
            if updates:
                conn.execute(f"UPDATE posts SET {', '.join(updates)} WHERE id = ?", params)
            if should_update_tags:
                normalized_tags = self._normalize_tags([new_category, new_class])
                self._replace_post_tags(conn, post_id, normalized_tags)
        refreshed = self.get_post(post_id)
        if refreshed is None:
            raise ValueError("未找到文章")
        return refreshed

    def delete_post(self, post_id: str) -> None:
        conn = self._conn()
        with conn:
            deleted = conn.execute("DELETE FROM posts WHERE id = ?", (post_id,))
            if deleted.rowcount == 0:
                raise ValueError("未找到文章")

    def favorite_post(self, post_id: str, username: str) -> bool:
        conn = self._conn()
        timestamp = utcnow_str()
        with conn:
            exists = conn.execute("SELECT 1 FROM posts WHERE id = ?", (post_id,)).fetchone()
            if not exists:
                raise ValueError("未找到文章")
            user_exists = conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
            if not user_exists:
                raise ValueError("未找到用户")
            result = conn.execute(
                "INSERT OR IGNORE INTO post_favorites (post_id, username, created_at) VALUES (?, ?, ?)",
                (post_id, username, timestamp),
            )
        return result.rowcount > 0

    def unfavorite_post(self, post_id: str, username: str) -> bool:
        conn = self._conn()
        with conn:
            result = conn.execute(
                "DELETE FROM post_favorites WHERE post_id = ? AND username = ?",
                (post_id, username),
            )
        return result.rowcount > 0

    def is_post_favorited(self, post_id: str, username: str) -> bool:
        conn = self._conn()
        row = conn.execute(
            "SELECT 1 FROM post_favorites WHERE post_id = ? AND username = ?",
            (post_id, username),
        ).fetchone()
        return row is not None

    def favorite_post_ids(self, username: str, post_ids: Optional[Iterable[str]] = None) -> Set[str]:
        conn = self._conn()
        if post_ids is None:
            rows = conn.execute(
                "SELECT post_id FROM post_favorites WHERE username = ?",
                (username,),
            ).fetchall()
        else:
            ids = [pid for pid in post_ids]
            if not ids:
                return set()
            placeholders = ",".join(["?"] * len(ids))
            rows = conn.execute(
                f"""
                SELECT post_id
                FROM post_favorites
                WHERE username = ? AND post_id IN ({placeholders})
                """,
                (username, *ids),
            ).fetchall()
        return {row["post_id"] for row in rows}

    def list_favorite_posts(self, username: str) -> List[Dict[str, Any]]:
        conn = self._conn()
        rows = conn.execute(
            """
            SELECT p.id, p.author, p.title, p.content, p.created_at, p.updated_at, p.category_tag, p.class_tag, pf.created_at AS favorited_at, p.is_hidden, p.is_pinned
            FROM post_favorites AS pf
            JOIN posts AS p ON pf.post_id = p.id
            WHERE pf.username = ?
            ORDER BY pf.created_at DESC
            """,
            (username,),
        ).fetchall()
        favorited_at_map = {row["id"]: row["favorited_at"] for row in rows}
        posts = self._build_posts_from_rows(rows)
        for post in posts:
            post["favorited_at"] = favorited_at_map.get(post["id"])
        return posts

    def favorite_count(self, post_id: str) -> int:
        conn = self._conn()
        row = conn.execute(
            "SELECT COUNT(*) AS count FROM post_favorites WHERE post_id = ?",
            (post_id,),
        ).fetchone()
        return int(row["count"] if row else 0)

    def add_comment(self, post_id: str, author: str, content: str) -> Dict[str, Any]:
        conn = self._conn()
        comment_id = uuid.uuid4().hex
        timestamp = utcnow_str()
        with conn:
            exists = conn.execute("SELECT 1 FROM posts WHERE id = ?", (post_id,)).fetchone()
            if not exists:
                raise ValueError("未找到文章")
            conn.execute(
                "INSERT INTO comments (id, post_id, author, content, created_at) VALUES (?, ?, ?, ?, ?)",
                (comment_id, post_id, author, content, timestamp),
            )
        return {
            "id": comment_id,
            "author": author,
            "content": content,
            "created_at": timestamp,
        }

    def delete_comment(self, post_id: str, comment_id: str) -> None:
        conn = self._conn()
        with conn:
            result = conn.execute(
                "DELETE FROM comments WHERE id = ? AND post_id = ?",
                (comment_id, post_id),
            )
            if result.rowcount == 0:
                raise ValueError("未找到评论")

    # Private messaging -------------------------------------------------

    @staticmethod
    def _message_row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "id": row["id"],
            "sender": row["sender"],
            "recipient": row["recipient"],
            "content": row["content"],
            "created_at": row["created_at"],
            "is_read": bool(row["is_read"]),
            "is_system": bool(row["is_system"]),
        }

    def get_message_preference(self, owner: str, other_user: str) -> MessagePreference:
        if owner == other_user:
            return MESSAGE_PREFERENCE_DEFAULT
        conn = self._conn()
        row = conn.execute(
            "SELECT preference FROM message_preferences WHERE owner = ? AND other_user = ?",
            (owner, other_user),
        ).fetchone()
        if not row:
            return MESSAGE_PREFERENCE_DEFAULT
        value = row["preference"]
        if value in MESSAGE_PREFERENCES:
            return cast(MessagePreference, value)
        return MESSAGE_PREFERENCE_DEFAULT

    def set_message_preference(self, owner: str, other_user: str, preference: MessagePreference) -> None:
        if owner == other_user:
            raise ValueError("不能对自己设置私信偏好")
        if preference not in MESSAGE_PREFERENCES:
            raise ValueError("不支持的私信偏好设置")
        if not self.get_user(other_user):
            raise ValueError("未找到目标用户")
        conn = self._conn()
        timestamp = utcnow_str()
        with conn:
            if preference == MESSAGE_PREFERENCE_DEFAULT:
                conn.execute(
                    "DELETE FROM message_preferences WHERE owner = ? AND other_user = ?",
                    (owner, other_user),
                )
            else:
                conn.execute(
                    """
                    INSERT INTO message_preferences (owner, other_user, preference, updated_at)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(owner, other_user) DO UPDATE
                        SET preference = excluded.preference, updated_at = excluded.updated_at
                    """,
                    (owner, other_user, preference, timestamp),
                )

    def send_private_message(
        self,
        sender: str,
        recipient: str,
        content: str,
        *,
        is_system: bool = False,
    ) -> Dict[str, Any]:
        prepared = content.strip()
        if not prepared:
            raise ValueError("消息内容不能为空")
        if sender == recipient:
            raise ValueError("不能向自己发送私信")
        if not is_system and not self.get_user(sender):
            raise ValueError("未找到发送者")
        if not self.get_user(recipient):
            raise ValueError("未找到收件人")
        preference = self.get_message_preference(recipient, sender) if not is_system else MESSAGE_PREFERENCE_DEFAULT
        if preference == "block" and not is_system:
            raise PermissionError("对方已设置拉黑，无法发送私信")
        message_id = uuid.uuid4().hex
        timestamp = utcnow_str()
        conn = self._conn()
        with conn:
            conn.execute(
                """
                INSERT INTO private_messages (
                    id, sender, recipient, content, created_at, is_read, is_system
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    message_id,
                    sender,
                    recipient,
                    prepared,
                    timestamp,
                    0,
                    1 if is_system else 0,
                ),
            )
        return {
            "id": message_id,
            "sender": sender,
            "recipient": recipient,
            "content": prepared,
            "created_at": timestamp,
            "is_read": False,
            "is_system": is_system,
        }

    def list_admin_users(self) -> List[Dict[str, Any]]:
        conn = self._conn()
        rows = conn.execute(
            "SELECT username, real_name FROM users WHERE role = 'admin' AND is_banned = 0"
        ).fetchall()
        return [
            {
                "username": row["username"],
                "real_name": row["real_name"],
            }
            for row in rows
        ]

    def send_system_notification(self, content: str) -> None:
        admins = self.list_admin_users()
        if not admins:
            logger.warning("系统通知未发送：当前没有管理员账户")
            return
        for admin in admins:
            username = admin["username"]
            try:
                self.send_private_message(
                    SYSTEM_USERNAME,
                    username,
                    content,
                    is_system=True,
                )
            except Exception:  # pragma: no cover - best effort
                logger.exception("发送系统通知给 %s 失败", username)

    def list_conversations(self, username: str) -> List[Dict[str, Any]]:
        conn = self._conn()
        rows = conn.execute(
            """
            WITH base AS (
                SELECT
                    id,
                    sender,
                    recipient,
                    content,
                    created_at,
                    is_read,
                    is_system,
                    CASE WHEN sender = :username THEN recipient ELSE sender END AS other_user
                FROM private_messages
                WHERE sender = :username OR recipient = :username
            ),
            ranked AS (
                SELECT
                    id,
                    sender,
                    recipient,
                    content,
                    created_at,
                    is_read,
                    is_system,
                    other_user,
                    ROW_NUMBER() OVER (PARTITION BY other_user ORDER BY created_at DESC) AS rn
                FROM base
            ),
            unread_counts AS (
                SELECT
                    other_user,
                    COUNT(*) AS unread_count
                FROM base
                WHERE recipient = :username AND is_read = 0
                GROUP BY other_user
            )
            SELECT
                r.other_user,
                r.id,
                r.sender,
                r.recipient,
                r.content,
                r.created_at,
                r.is_system,
                COALESCE(u.unread_count, 0) AS unread_count,
                COALESCE(pref.preference, :default_pref) AS preference
            FROM ranked AS r
            LEFT JOIN unread_counts AS u ON u.other_user = r.other_user
            LEFT JOIN message_preferences AS pref
                ON pref.owner = :username AND pref.other_user = r.other_user
            WHERE r.rn = 1
            ORDER BY r.created_at DESC
            """,
            {
                "username": username,
                "default_pref": MESSAGE_PREFERENCE_DEFAULT,
            },
        ).fetchall()
        conversations: List[Dict[str, Any]] = []
        for row in rows:
            conversations.append(
                {
                    "user": row["other_user"],
                    "last_message": {
                        "id": row["id"],
                        "sender": row["sender"],
                        "recipient": row["recipient"],
                        "content": row["content"],
                        "created_at": row["created_at"],
                        "is_system": bool(row["is_system"]),
                    },
                    "unread_count": int(row["unread_count"]),
                    "preference": row["preference"],
                }
            )
        return conversations

    def get_conversation_messages(
        self,
        username: str,
        other_user: str,
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        params: List[Any] = [username, other_user, other_user, username]
        query = """
            SELECT id, sender, recipient, content, created_at, is_read, is_system
            FROM private_messages
            WHERE (sender = ? AND recipient = ?) OR (sender = ? AND recipient = ?)
            ORDER BY created_at ASC
        """
        if limit is not None:
            query += " LIMIT ?"
            params.append(limit)
        conn = self._conn()
        rows = conn.execute(query, params).fetchall()
        return [self._message_row_to_dict(row) for row in rows]

    def mark_conversation_read(self, username: str, other_user: str) -> None:
        conn = self._conn()
        with conn:
            conn.execute(
                """
                UPDATE private_messages
                SET is_read = 1
                WHERE sender = ? AND recipient = ? AND is_read = 0
                """,
                (other_user, username),
            )

    def count_unread_messages(self, username: str, notify_only: bool = True) -> int:
        conn = self._conn()
        row = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM private_messages AS pm
            LEFT JOIN message_preferences AS pref
                ON pref.owner = ? AND pref.other_user = pm.sender
            WHERE pm.recipient = ?
              AND pm.is_read = 0
              AND (? = 0 OR COALESCE(pref.preference, ?) = 'notify')
            """,
            (
                username,
                username,
                1 if notify_only else 0,
                MESSAGE_PREFERENCE_DEFAULT,
            ),
        ).fetchone()
        return int(row["count"] if row else 0)

    # Normal tags ------------------------------------------------------

    def list_normal_tags(self) -> List[str]:
        conn = self._conn()
        rows = conn.execute("SELECT name FROM normal_tags ORDER BY name").fetchall()
        return [row["name"] for row in rows]

    def list_category_tags(self) -> List[str]:
        conn = self._conn()
        rows = conn.execute("SELECT name FROM normal_tags WHERE is_column = 0 ORDER BY name").fetchall()
        return [row["name"] for row in rows]

    def list_column_tags(self) -> List[str]:
        conn = self._conn()
        rows = conn.execute(
            "SELECT name FROM normal_tags WHERE is_column = 1 ORDER BY name"
        ).fetchall()
        return [row["name"] for row in rows]

    def list_common_tags(self) -> List[str]:
        return self.list_category_tags()

    def add_category_tag(self, tag: str) -> None:
        name = (tag or "").strip()
        if not name:
            raise ValueError("类别标签名称不能为空")
        conn = self._conn()
        with conn:
            conn.execute(
                "INSERT OR IGNORE INTO normal_tags (name, is_column) VALUES (?, 0)",
                (name,),
            )

    def remove_category_tag(self, tag: str) -> None:
        name = (tag or "").strip()
        if not name:
            raise ValueError("未指定类别标签")
        conn = self._conn()
        with conn:
            affected_posts = [row["id"] for row in conn.execute("SELECT id FROM posts WHERE category_tag = ?", (name,))]
            self._ensure_category_exists(conn, DEFAULT_CATEGORY_TAG)
            conn.execute("DELETE FROM normal_tags WHERE name = ?", (name,))
            conn.execute("UPDATE posts SET category_tag = ? WHERE category_tag = ?", (DEFAULT_CATEGORY_TAG, name))
            for post_id in affected_posts:
                tag_rows = conn.execute("SELECT tag FROM post_tags WHERE post_id = ?", (post_id,)).fetchall()
                tags = [DEFAULT_CATEGORY_TAG] + [row["tag"] for row in tag_rows if row["tag"] != name]
                self._replace_post_tags(conn, post_id, self._normalize_tags(tags))

    # Class tags ------------------------------------------------------

    def list_class_tags(self, *, with_meta: bool = False, auto_sync: bool = False) -> List[Dict[str, object] | str]:
        if auto_sync:
            try:
                self.sync_class_tags_from_oj()
            except OJServiceUnavailable:
                pass
        conn = self._conn()
        rows = conn.execute(
            "SELECT name, source, external_id FROM class_tags ORDER BY source, name"
        ).fetchall()
        if with_meta:
            return [
                {
                    "name": row["name"],
                    "source": row["source"],
                    "external_id": row["external_id"],
                }
                for row in rows
            ]
        return [row["name"] for row in rows]

    def add_class_tag(self, tag: str, *, source: str = "manual", external_id: str | None = None) -> None:
        name = (tag or "").strip()
        if not name:
            raise ValueError("标签名称不能为空")
        conn = self._conn()
        with conn:
            conn.execute(
                """
                INSERT INTO class_tags (name, source, external_id)
                VALUES (?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET source = excluded.source, external_id = excluded.external_id
                """,
                (name, source, external_id),
            )
            conn.execute(
                """
                INSERT OR IGNORE INTO class_groups (tag, display_name, last_synced_at)
                VALUES (?, ?, ?)
                """,
                (name, name, utcnow_str()),
            )

    def remove_class_tag(self, tag: str) -> None:
        name = (tag or "").strip()
        if not name:
            raise ValueError("未指定班级标签")
        conn = self._conn()
        with conn:
            affected_posts = [row["id"] for row in conn.execute("SELECT id FROM posts WHERE class_tag = ?", (name,))]
            self._ensure_class_exists(conn, DEFAULT_CLASS_TAG)
            conn.execute("DELETE FROM class_tags WHERE name = ?", (name,))
            conn.execute("DELETE FROM class_groups WHERE tag = ?", (name,))
            conn.execute("UPDATE posts SET class_tag = ? WHERE class_tag = ?", (DEFAULT_CLASS_TAG, name))
            for post_id in affected_posts:
                tag_rows = conn.execute("SELECT tag FROM post_tags WHERE post_id = ?", (post_id,)).fetchall()
                tags = [DEFAULT_CLASS_TAG] + [row["tag"] for row in tag_rows if row["tag"] != name]
                self._replace_post_tags(conn, post_id, self._normalize_tags(tags))

    def sync_class_tags_from_oj(self) -> Dict[str, int]:
        groups = self._oj_client.fetch_groups_public()
        conn = self._conn()
        with conn:
            existing_rows = conn.execute(
                "SELECT name, source, external_id FROM class_tags"
            ).fetchall()
        existing_by_ext = {
            row["external_id"]: row for row in existing_rows if row["external_id"]
        }
        existing_by_name = {row["name"]: row for row in existing_rows}
        added = 0
        updated = 0
        removed = 0
        seen_ext: set[str] = set()
        seen_names: set[str] = set()
        with conn:
            for group in groups:
                if isinstance(group, dict):
                    gid_raw = group.get("external_id") or group.get("id")
                    name_raw = group.get("display_name") or group.get("name") or group.get("tag")
                else:
                    gid_raw = getattr(group, "external_id", None)
                    name_raw = getattr(group, "display_name", None) or getattr(group, "tag", None)
                gid = str(gid_raw or "").strip() or None
                name = str(name_raw or "").strip()
                if not name:
                    continue
                if gid and gid in existing_by_ext:
                    current = existing_by_ext[gid]
                    if current["name"] != name:
                        conn.execute("DELETE FROM class_tags WHERE name = ?", (current["name"],))
                        added += 1
                    else:
                        updated += 1
                elif name in existing_by_name:
                    if existing_by_name[name]["source"] not in {"oj", "builtin"}:
                        continue
                    updated += 1
                else:
                    added += 1
                conn.execute(
                    """
                    INSERT OR REPLACE INTO class_tags (name, source, external_id)
                    VALUES (?, 'oj', ?)
                    """,
                    (name, gid),
                )
                conn.execute(
                    """
                    INSERT OR REPLACE INTO class_groups (tag, display_name, last_synced_at)
                    VALUES (?, ?, ?)
                    """,
                    (name, name, utcnow_str()),
                )
                if gid:
                    seen_ext.add(gid)
                seen_names.add(name)
            stale = [
                row["name"]
                for row in existing_rows
                if row["source"] == "oj"
                and (
                    (row["external_id"] and row["external_id"] not in seen_ext)
                    or (not row["external_id"] and row["name"] not in seen_names)
                )
            ]
            if stale:
                removed = len(stale)
                conn.executemany("DELETE FROM class_tags WHERE name = ?", [(name,) for name in stale])
                conn.executemany("DELETE FROM class_groups WHERE tag = ?", [(name,) for name in stale])
        return {"added": added, "updated": updated, "removed": removed}

    # Class groups ----------------------------------------------------

    def list_class_groups(self) -> List[Dict[str, Any]]:
        conn = self._conn()
        rows = conn.execute(
            "SELECT tag, display_name, last_synced_at FROM class_groups ORDER BY display_name"
        ).fetchall()
        return [
            {
                "tag": row["tag"],
                "display_name": row["display_name"],
                "last_synced_at": row["last_synced_at"],
            }
            for row in rows
        ]

    def class_memberships(self) -> Dict[str, List[Dict[str, str]]]:
        conn = self._conn()
        rows = conn.execute(
            "SELECT class_tag, username, real_name FROM class_memberships ORDER BY class_tag, username"
        ).fetchall()
        result: Dict[str, List[Dict[str, str]]] = {}
        for row in rows:
            result.setdefault(row["class_tag"], []).append(
                {
                    "username": row["username"],
                    "real_name": row["real_name"] or "",
                }
            )
        return result

    def user_class_tags(self, username: str) -> List[str]:
        conn = self._conn()
        rows = conn.execute(
            "SELECT class_tag FROM class_memberships WHERE username = ? ORDER BY class_tag",
            (username,),
        ).fetchall()
        return [row["class_tag"] for row in rows]

    def update_class_groups_from_credentials(self, username: str, password: str) -> None:
        if not self._oj_client:
            return
        now = datetime.now(timezone.utc)
        if not self._try_acquire_class_sync_lock(now):
            return
        try:
            groups = self._fetch_groups_with_retry(username, password)
            if self._sync_class_groups(groups):
                self._set_metadata_value("class_sync_last_run", now.strftime(ISO_FORMAT))
        except OJInvalidCredentials:
            return
        except OJAccountNotFound:
            self.send_system_notification(f"班级同步失败：OJ 账号 {username} 不存在或不可访问。")
            return
        except OJServiceUnavailable as exc:
            self.send_system_notification(f"班级同步失败：无法访问 BNDSOJ（{exc}）。")
            return
        finally:
            self._release_class_sync_lock()

    def update_class_groups_from_cookie(self, phpsessid: str) -> None:
        if not self._oj_client:
            return
        now = datetime.now(timezone.utc)
        if not self._try_acquire_class_sync_lock(now):
            return
        try:
            groups = self._fetch_groups_with_retry_cookie(phpsessid)
            if self._sync_class_groups(groups):
                self._set_metadata_value("class_sync_last_run", now.strftime(ISO_FORMAT))
        except OJInvalidCredentials:
            return
        except OJServiceUnavailable as exc:
            self.send_system_notification(f"班级同步失败：无法访问 BNDSOJ（{exc}）。")
            return
        finally:
            self._release_class_sync_lock()

    def _fetch_groups_with_retry(self, username: str, password: str, *, retries: int = 3, delay: float = 0.8) -> List[OJGroup]:
        attempt = 0
        last_error: Exception | None = None
        while attempt < max(1, retries):
            try:
                return self._oj_client.fetch_groups(username, password)
            except OJServiceUnavailable as exc:
                last_error = exc
                attempt += 1
                if attempt >= retries:
                    break
                time.sleep(delay)
            except Exception as exc:
                last_error = exc
                break
        if last_error:
            raise last_error
        return []

    def _fetch_groups_with_retry_cookie(self, phpsessid: str, *, retries: int = 3, delay: float = 0.8) -> List[OJGroup]:
        attempt = 0
        last_error: Exception | None = None
        while attempt < max(1, retries):
            try:
                return self._oj_client.fetch_groups_with_cookie(phpsessid)
            except OJServiceUnavailable as exc:
                last_error = exc
                attempt += 1
                if attempt >= retries:
                    break
                time.sleep(delay)
            except Exception as exc:
                last_error = exc
                break
        if last_error:
            raise last_error
        return []

    def _sync_class_groups(self, groups: List[OJGroup]) -> bool:
        if not groups:
            logger.warning("班级同步返回空结果，保留现有数据")
            self.send_system_notification("班级同步失败：未获取到任何小组信息，请检查 BNDSOJ 状态。")
            return False

        timestamp = utcnow_str()
        previous_groups = {group["tag"]: group for group in self.list_class_groups()}
        previous_memberships = self.class_memberships()

        prepared_groups: List[Tuple[str, str, List[OJGroupMember], str]] = []
        class_tags: Set[str] = set()
        external_ids: Dict[str, str | None] = {}
        memberships_by_user: Dict[str, Set[str]] = {}
        real_name_by_user: Dict[str, str] = {}

        fallback_groups: List[str] = []
        for group in groups:
            tag = (group.tag or "").strip()
            if not tag:
                continue
            display = (group.display_name or "").strip() or tag
            members = list(group.members)
            memberships_complete = getattr(group, "memberships_complete", True)
            ext_id = str(getattr(group, "external_id", "") or "").strip() or None

            if (not members or not memberships_complete) and tag in previous_memberships:
                fallback_members = previous_memberships.get(tag, [])
                if fallback_members:
                    members = [
                        OJGroupMember(
                            username=(record.get("username", "") or ""),
                            real_name=(record.get("real_name", "") or ""),
                        )
                        for record in fallback_members
                        if record.get("username")
                    ]
                    memberships_complete = True
                    logger.info("班级 %s 使用上次同步的成员列表（远端数据不可用）", tag)
                    fallback_groups.append(display)

            if not members and not memberships_complete:
                logger.warning("无法获取班级 %s 成员信息，将保留现有成员列表", tag)
                fallback_members = previous_memberships.get(tag, [])
                if fallback_members:
                    members = [
                        OJGroupMember(
                            username=(record.get("username", "") or ""),
                            real_name=(record.get("real_name", "") or ""),
                        )
                        for record in fallback_members
                        if record.get("username")
                    ]
                    memberships_complete = True
                    fallback_groups.append(display)

            class_tags.add(tag)
            external_ids[tag] = ext_id
            last_synced = timestamp if memberships_complete else previous_groups.get(tag, {}).get("last_synced_at", timestamp)
            prepared_groups.append((tag, display, members, last_synced))

            for member in members:
                username = (member.username or "").strip()
                if not username:
                    continue
                memberships_by_user.setdefault(username, set()).add(tag)
                display_name = (member.real_name or "").strip()
                if display_name and username not in real_name_by_user:
                    real_name_by_user[username] = display_name

        if not class_tags:
            logger.warning("班级同步未解析到有效标签，跳过更新")
            return False

        conn = self._conn()
        with conn:
            existing_group_tags = set(previous_groups.keys())
            existing_class_tag_rows = conn.execute("SELECT name, source FROM class_tags").fetchall()
            existing_class_tag_by_name = {row["name"]: row for row in existing_class_tag_rows}
            if class_tags:
                placeholders = ",".join(["?"] * len(class_tags))
                conn.execute(
                    f"DELETE FROM class_groups WHERE tag NOT IN ({placeholders})",
                    tuple(class_tags),
                )
            else:
                conn.execute("DELETE FROM class_groups")
            conn.execute("DELETE FROM class_memberships")

            for tag, display, members, last_synced in prepared_groups:
                if not tag:
                    continue
                conn.execute(
                    """
                    INSERT OR REPLACE INTO class_groups (tag, display_name, last_synced_at)
                    VALUES (?, ?, ?)
                    """,
                    (tag, display, last_synced),
                )
                member_rows = [
                    (tag, (member.username or "").strip(), (member.real_name or "").strip())
                    for member in members
                    if (member.username or "").strip()
                ]
                if member_rows:
                    conn.executemany(
                        """
                        INSERT OR REPLACE INTO class_memberships (class_tag, username, real_name)
                        VALUES (?, ?, ?)
                        """,
                        member_rows,
                    )

                for tag in class_tags:
                    current = existing_class_tag_by_name.get(tag)
                    if current and current["source"] not in {"oj", "builtin"}:
                        continue
                    conn.execute(
                        """
                        INSERT INTO class_tags (name, source, external_id)
                        VALUES (?, 'oj', ?)
                        ON CONFLICT(name) DO UPDATE SET source = excluded.source, external_id = excluded.external_id
                        """,
                        (tag, external_ids.get(tag)),
                    )
                stale_class_tags = [
                    row["name"]
                    for row in existing_class_tag_rows
                    if row["source"] == "oj" and row["name"] not in class_tags
                ]
                if stale_class_tags:
                    conn.executemany("DELETE FROM class_tags WHERE name = ?", [(name,) for name in stale_class_tags])
            removed_class_tags = existing_group_tags - class_tags
            if removed_class_tags:
                pass

        all_users = self.list_users()
        existing_usernames = {user["username"] for user in all_users}
        for user in all_users:
            username = user["username"]
            remote_real_name = real_name_by_user.get(username)
            if remote_real_name and remote_real_name != (user.get("real_name") or ""):
                try:
                    self.update_user_real_name(username, remote_real_name)
                except ValueError:
                    pass

        for username, tags in memberships_by_user.items():
            if username in existing_usernames:
                continue
            try:
                self.create_user(
                    username=username,
                    password=uuid.uuid4().hex,
                    real_name=real_name_by_user.get(username, ""),
                )
            except ValueError:
                display_name = real_name_by_user.get(username)
                if display_name:
                    try:
                        self.update_user_real_name(username, display_name)
                    except ValueError:
                        pass

        if fallback_groups:
            self.send_system_notification(
                "班级同步提醒：以下小组未能从 BNDSOJ 获取最新成员，已沿用上次同步数据："
                + ", ".join(sorted(set(fallback_groups)))
            )

        return True

    def build_class_column_tree(self) -> Dict[str, Any]:
        class_groups = self.list_class_groups()
        column_tags = self.list_column_tags()

        nodes: Dict[str, Dict[str, Any]] = {}
        root_children: List[str] = []
        nodes["root"] = {"id": "root", "tag": None, "children": []}

        for class_group in class_groups:
            class_tag = (class_group.get("tag") or "").strip()
            if not class_tag:
                continue
            class_node_id = _stable_node_id("class", class_tag)
            nodes[class_node_id] = {"id": class_node_id, "tag": class_tag, "children": []}
            root_children.append(class_node_id)
            for column_tag in column_tags:
                column_value = (column_tag or "").strip()
                if not column_value:
                    continue
                column_node_id = _stable_node_id("column", f"{class_tag}::{column_value}")
                nodes[column_node_id] = {
                    "id": column_node_id,
                    "tag": column_value,
                    "children": [],
                }
                nodes[class_node_id]["children"].append(column_node_id)

        nodes["root"]["children"] = root_children
        return {"nodes": list(nodes.values())}

    @staticmethod
    def _ensure_category_exists(conn: sqlite3.Connection, tag: str) -> None:
        name = (tag or "").strip()
        if not name:
            return
        conn.execute("INSERT OR IGNORE INTO normal_tags (name, is_column) VALUES (?, 0)", (name,))

    @staticmethod
    def _ensure_class_exists(
            conn: sqlite3.Connection,
        tag: str,
        *,
        source: str = "manual",
        external_id: str | None = None,
    ) -> None:
        name = (tag or "").strip()
        if not name:
            return
        conn.execute(
            """
            INSERT OR IGNORE INTO class_tags (name, source, external_id)
            VALUES (?, ?, ?)
            """,
            (name, source, external_id),
        )
        conn.execute(
            """
            INSERT OR IGNORE INTO class_groups (tag, display_name, last_synced_at)
            VALUES (?, ?, ?)
            """,
            (name, name, utcnow_str()),
        )

    def _ensure_tag_defaults(self, conn: sqlite3.Connection) -> None:
        with conn:
            self._ensure_category_exists(conn, DEFAULT_CATEGORY_TAG)
            self._ensure_class_exists(conn, DEFAULT_CLASS_TAG, source="builtin", external_id=None)

    def _migrate_post_tag_columns(self, conn: sqlite3.Connection) -> None:
        with conn:
            rows = conn.execute("SELECT id, category_tag, class_tag FROM posts").fetchall()
        for row in rows:
            category = (row["category_tag"] or "").strip()
            class_tag = (row["class_tag"] or "").strip()
            if category and class_tag:
                continue
            tags_map = self._load_tags_for_posts(conn, [row["id"]])
            tags = tags_map.get(row["id"], [])
            resolved_category = category or (tags[0] if tags else DEFAULT_CATEGORY_TAG)
            resolved_class = class_tag or (tags[1] if len(tags) > 1 else DEFAULT_CLASS_TAG)
            with conn:
                self._ensure_category_exists(conn, resolved_category)
                self._ensure_class_exists(conn, resolved_class, source="migration" if class_tag or tags else "builtin")
                conn.execute(
                    "UPDATE posts SET category_tag = ?, class_tag = ? WHERE id = ?",
                    (resolved_category, resolved_class, row["id"]),
                )

    def add_normal_tag(self, tag: str, *, is_column: bool = False) -> None:
        name = (tag or "").strip()
        if not name:
            raise ValueError("标签名称不能为空")
        conn = self._conn()
        with conn:
            existing = conn.execute(
                "SELECT is_column FROM normal_tags WHERE name = ?",
                (name,),
            ).fetchone()
            if existing:
                if is_column and not existing["is_column"]:
                    conn.execute(
                        "UPDATE normal_tags SET is_column = 1 WHERE name = ?",
                        (name,),
                    )
            else:
                conn.execute(
                    "INSERT INTO normal_tags (name, is_column) VALUES (?, ?)",
                    (name, 1 if is_column else 0),
                )

    def remove_normal_tag(self, tag: str) -> None:
        conn = self._conn()
        with conn:
            conn.execute("DELETE FROM normal_tags WHERE name = ?", (tag,))

    # Query helpers ----------------------------------------------------

    def posts_with_tags(self, required_tags: Iterable[str]) -> List[Dict[str, Any]]:
        tags = self._normalize_tags(required_tags)
        if not tags:
            return self.list_posts()
        conn = self._conn()
        placeholders = ",".join(["?"] * len(tags))
        rows = conn.execute(
            f"""
            SELECT p.id, p.author, p.title, p.content, p.created_at, p.updated_at, p.category_tag, p.class_tag, p.is_hidden, p.is_pinned
            FROM posts AS p
            JOIN post_tags AS pt ON p.id = pt.post_id
            WHERE pt.tag IN ({placeholders})
            GROUP BY p.id
            HAVING COUNT(DISTINCT pt.tag) = ?
            ORDER BY p.created_at DESC
            """,
            (*tags, len(tags)),
        ).fetchall()
        return self._build_posts_from_rows(rows)

    # Internal helpers -------------------------------------------------

    @staticmethod
    def _replace_post_tags(conn: sqlite3.Connection, post_id: str, tags: Sequence[str]) -> None:
        conn.execute("DELETE FROM post_tags WHERE post_id = ?", (post_id,))
        if tags:
            conn.executemany(
                "INSERT INTO post_tags (post_id, tag) VALUES (?, ?)",
                [(post_id, tag) for tag in tags],
            )

    def _build_posts_from_rows(self, rows: Sequence[sqlite3.Row]) -> List[Dict[str, Any]]:
        if not rows:
            return []
        conn = self._conn()
        post_ids = [row["id"] for row in rows]
        tags_map = self._load_tags_for_posts(conn, post_ids)
        comments_map = self._load_comments_for_posts(conn, post_ids)
        favorite_counts = self._load_favorite_counts(conn, post_ids)
        posts: List[Dict[str, Any]] = []
        for row in rows:
            post_id = row["id"]
            posts.append(
                {
                    "id": post_id,
                    "author": row["author"],
                    "title": row["title"],
                    "content": row["content"],
                    "category_tag": row["category_tag"] or DEFAULT_CATEGORY_TAG,
                    "class_tag": row["class_tag"] or DEFAULT_CLASS_TAG,
                    "tags": tags_map.get(post_id, []),
                    "created_at": row["created_at"],
                    "updated_at": row["updated_at"],
                    "comments": comments_map.get(post_id, []),
                    "favorite_count": favorite_counts.get(post_id, 0),
                    "is_hidden": bool(row["is_hidden"]) if "is_hidden" in row.keys() else False,
                    "is_pinned": bool(row["is_pinned"]) if "is_pinned" in row.keys() else False,
                }
            )
        return posts

    @staticmethod
    def _load_tags_for_posts(conn: sqlite3.Connection, post_ids: Sequence[str]) -> Dict[str, List[str]]:
        if not post_ids:
            return {}
        placeholders = ",".join(["?"] * len(post_ids))
        rows = conn.execute(
            f"SELECT post_id, tag FROM post_tags WHERE post_id IN ({placeholders})",
            post_ids,
        ).fetchall()
        result: Dict[str, List[str]] = {post_id: [] for post_id in post_ids}
        for row in rows:
            result.setdefault(row["post_id"], []).append(row["tag"])
        for tags in result.values():
            tags.sort()
        return result

    @staticmethod
    def _load_comments_for_posts(conn: sqlite3.Connection, post_ids: Sequence[str]) -> Dict[str, List[Dict[str, Any]]]:
        if not post_ids:
            return {}
        placeholders = ",".join(["?"] * len(post_ids))
        rows = conn.execute(
            f"""
            SELECT id, post_id, author, content, created_at
            FROM comments
            WHERE post_id IN ({placeholders})
            ORDER BY created_at
            """,
            post_ids,
        ).fetchall()
        result: Dict[str, List[Dict[str, Any]]] = {post_id: [] for post_id in post_ids}
        for row in rows:
            result.setdefault(row["post_id"], []).append(
                {
                    "id": row["id"],
                    "author": row["author"],
                    "content": row["content"],
                    "created_at": row["created_at"],
                }
            )
        return result

    @staticmethod
    def _load_favorite_counts(conn: sqlite3.Connection, post_ids: Sequence[str]) -> Dict[str, int]:
        if not post_ids:
            return {}
        placeholders = ",".join(["?"] * len(post_ids))
        rows = conn.execute(
            f"""
            SELECT post_id, COUNT(*) AS count
            FROM post_favorites
            WHERE post_id IN ({placeholders})
            GROUP BY post_id
            """,
            post_ids,
        ).fetchall()
        return {row["post_id"]: int(row["count"]) for row in rows}

    @staticmethod
    def _normalize_tags(tags: Optional[Iterable[str]]) -> List[str]:
        if not tags:
            return []
        normalized = {
            tag.strip()
            for tag in tags
            if isinstance(tag, str) and tag.strip()
        }
        return sorted(normalized)

    @staticmethod
    def _deserialize_tags(payload: str) -> List[str]:
        if not payload:
            return []
        try:
            loaded = json.loads(payload)
        except json.JSONDecodeError:
            return []
        if not isinstance(loaded, list):
            return []
        return [str(item) for item in loaded if isinstance(item, str)]

    # Post pinning -----------------------------------------------------

    def set_post_pinned(self, post_id: str, pinned: bool) -> None:
        conn = self._conn()
        with conn:
            updated = conn.execute(
                "UPDATE posts SET is_pinned = ? WHERE id = ?",
                (1 if pinned else 0, post_id),
            )
            if updated.rowcount == 0:
                raise ValueError("未找到文章")

    # Upload / image hosting -------------------------------------------

    DEFAULT_QUOTA_BYTES = 1 * 1024 * 1024 * 1024  # 1 GB

    def get_user_quota(self, username: str) -> int:
        conn = self._conn()
        row = conn.execute(
            "SELECT quota_bytes FROM user_quotas WHERE username = ?",
            (username,),
        ).fetchone()
        if row:
            return int(row["quota_bytes"])
        return self.DEFAULT_QUOTA_BYTES

    def set_user_quota(self, username: str, quota_bytes: int) -> None:
        conn = self._conn()
        with conn:
            conn.execute(
                """INSERT INTO user_quotas (username, quota_bytes) VALUES (?, ?)
                   ON CONFLICT(username) DO UPDATE SET quota_bytes = excluded.quota_bytes""",
                (username, max(0, quota_bytes)),
            )

    def batch_set_user_quotas(self, usernames: list[str], quota_gb: float) -> None:
        """Batch update quotas for multiple users."""
        if not usernames:
            return
        quota_bytes = int(quota_gb * (1024 ** 3))
        conn = self._conn()
        with conn:
            for username in usernames:
                conn.execute(
                    """INSERT INTO user_quotas (username, quota_bytes) VALUES (?, ?)
                       ON CONFLICT(username) DO UPDATE SET quota_bytes = excluded.quota_bytes""",
                    (username, max(0, quota_bytes)),
                )

    def get_user_used_space(self, username: str) -> int:
        conn = self._conn()
        row = conn.execute(
            "SELECT COALESCE(SUM(file_size), 0) AS used FROM user_uploads WHERE username = ?",
            (username,),
        ).fetchone()
        uploads_used = int(row["used"]) if row else 0
        row2 = conn.execute(
            "SELECT COALESCE(SUM(file_size), 0) AS used FROM drive_files WHERE username = ? AND is_folder = 0",
            (username,),
        ).fetchone()
        drive_used = int(row2["used"]) if row2 else 0
        return uploads_used + drive_used

    def check_quota(self, username: str, additional_bytes: int) -> bool:
        quota = self.get_user_quota(username)
        used = self.get_user_used_space(username)
        return (used + additional_bytes) <= quota

    def add_upload(self, username: str, filename: str, original_name: str,
                   mime_type: str, file_size: int, storage_type: str,
                   storage_url: str) -> Dict[str, Any]:
        upload_id = uuid.uuid4().hex
        timestamp = utcnow_str()
        conn = self._conn()
        with conn:
            conn.execute(
                """INSERT INTO user_uploads (id, username, filename, original_name, mime_type,
                   file_size, storage_type, storage_url, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (upload_id, username, filename, original_name, mime_type,
                 file_size, storage_type, storage_url, timestamp),
            )
        return {
            "id": upload_id, "username": username, "filename": filename,
            "original_name": original_name, "mime_type": mime_type,
            "file_size": file_size, "storage_type": storage_type,
            "storage_url": storage_url, "created_at": timestamp,
        }

    def list_uploads(self, username: str) -> List[Dict[str, Any]]:
        conn = self._conn()
        rows = conn.execute(
            "SELECT * FROM user_uploads WHERE username = ? ORDER BY created_at DESC",
            (username,),
        ).fetchall()
        return [dict(row) for row in rows]

    def get_upload(self, upload_id: str) -> Optional[Dict[str, Any]]:
        conn = self._conn()
        row = conn.execute("SELECT * FROM user_uploads WHERE id = ?", (upload_id,)).fetchone()
        return dict(row) if row else None

    def delete_upload(self, upload_id: str) -> Optional[Dict[str, Any]]:
        conn = self._conn()
        row = conn.execute("SELECT * FROM user_uploads WHERE id = ?", (upload_id,)).fetchone()
        if not row:
            return None
        record = dict(row)
        with conn:
            conn.execute("DELETE FROM user_uploads WHERE id = ?", (upload_id,))
        return record

    # Cloud drive ------------------------------------------------------

    def add_drive_file(self, username: str, filename: str, original_name: str,
                       mime_type: str, file_size: int, parent_id: Optional[str] = None,
                       is_folder: bool = False) -> Dict[str, Any]:
        file_id = uuid.uuid4().hex
        timestamp = utcnow_str()
        conn = self._conn()
        with conn:
            if parent_id:
                parent = conn.execute(
                    "SELECT id FROM drive_files WHERE id = ? AND username = ? AND is_folder = 1",
                    (parent_id, username),
                ).fetchone()
                if not parent:
                    raise ValueError("父文件夹不存在")
            conn.execute(
                """INSERT INTO drive_files (id, username, filename, original_name, mime_type,
                   file_size, parent_id, is_folder, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (file_id, username, filename, original_name, mime_type,
                 file_size, parent_id, 1 if is_folder else 0, timestamp, timestamp),
            )
        return {
            "id": file_id, "username": username, "filename": filename,
            "original_name": original_name, "mime_type": mime_type,
            "file_size": file_size, "parent_id": parent_id,
            "is_folder": is_folder, "created_at": timestamp, "updated_at": timestamp,
        }

    def list_drive_files(self, username: str, parent_id: Optional[str] = None) -> List[Dict[str, Any]]:
        conn = self._conn()
        if parent_id:
            rows = conn.execute(
                "SELECT * FROM drive_files WHERE username = ? AND parent_id = ? ORDER BY is_folder DESC, original_name",
                (username, parent_id),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM drive_files WHERE username = ? AND parent_id IS NULL ORDER BY is_folder DESC, original_name",
                (username,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_drive_file(self, file_id: str) -> Optional[Dict[str, Any]]:
        conn = self._conn()
        row = conn.execute("SELECT * FROM drive_files WHERE id = ?", (file_id,)).fetchone()
        return dict(row) if row else None

    def rename_drive_file(self, file_id: str, new_name: str) -> None:
        conn = self._conn()
        with conn:
            conn.execute(
                "UPDATE drive_files SET original_name = ?, updated_at = ? WHERE id = ?",
                (new_name, utcnow_str(), file_id),
            )

    def delete_drive_file(self, file_id: str) -> Optional[Dict[str, Any]]:
        conn = self._conn()
        row = conn.execute("SELECT * FROM drive_files WHERE id = ?", (file_id,)).fetchone()
        if not row:
            return None
        record = dict(row)
        with conn:
            if record["is_folder"]:
                self._delete_drive_folder_recursive(conn, file_id, record["username"])
            conn.execute("DELETE FROM drive_files WHERE id = ?", (file_id,))
        return record

    def _delete_drive_folder_recursive(self, conn: sqlite3.Connection, folder_id: str, username: str) -> List[Dict[str, Any]]:
        children = conn.execute(
            "SELECT id, is_folder, filename FROM drive_files WHERE parent_id = ? AND username = ?",
            (folder_id, username),
        ).fetchall()
        deleted = []
        for child in children:
            if child["is_folder"]:
                deleted.extend(self._delete_drive_folder_recursive(conn, child["id"], username))
            deleted.append(dict(child))
            conn.execute("DELETE FROM drive_files WHERE id = ?", (child["id"],))
        return deleted

    def get_drive_path(self, file_id: str) -> List[Dict[str, Any]]:
        conn = self._conn()
        path = []
        current_id = file_id
        while current_id:
            row = conn.execute("SELECT id, original_name, parent_id FROM drive_files WHERE id = ?", (current_id,)).fetchone()
            if not row:
                break
            path.insert(0, {"id": row["id"], "name": row["original_name"]})
            current_id = row["parent_id"]
        return path

    # Drive shares -----------------------------------------------------

    def create_drive_share(self, file_id: str, owner_username: str,
                           invite_code: Optional[str] = None,
                           expires_at: Optional[str] = None,
                           max_downloads: Optional[int] = None,
                           require_login: bool = False) -> Dict[str, Any]:
        share_id = uuid.uuid4().hex
        share_token = secrets.token_urlsafe(20)
        timestamp = utcnow_str()
        conn = self._conn()
        with conn:
            conn.execute(
                """INSERT INTO drive_shares (id, file_id, owner_username, share_token,
                   invite_code, expires_at, max_downloads, require_login, download_count, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?)""",
                (share_id, file_id, owner_username, share_token,
                 invite_code or None, expires_at or None, max_downloads,
                 1 if require_login else 0, timestamp),
            )
        return {
            "id": share_id, "file_id": file_id, "owner_username": owner_username,
            "share_token": share_token, "invite_code": invite_code,
            "expires_at": expires_at, "max_downloads": max_downloads,
            "require_login": require_login, "download_count": 0, "created_at": timestamp,
        }

    def get_drive_share_by_token(self, token: str) -> Optional[Dict[str, Any]]:
        conn = self._conn()
        row = conn.execute("SELECT * FROM drive_shares WHERE share_token = ?", (token,)).fetchone()
        return dict(row) if row else None

    def get_drive_file_shares(self, file_id: str, owner_username: str) -> List[Dict[str, Any]]:
        conn = self._conn()
        rows = conn.execute(
            "SELECT * FROM drive_shares WHERE file_id = ? AND owner_username = ? ORDER BY created_at DESC",
            (file_id, owner_username),
        ).fetchall()
        return [dict(row) for row in rows]

    def list_drive_owner_shares(self, owner_username: str) -> List[Dict[str, Any]]:
        conn = self._conn()
        rows = conn.execute(
            """SELECT s.*, f.original_name AS file_name, f.file_size, f.updated_at AS file_updated_at
               FROM drive_shares AS s
               JOIN drive_files AS f ON f.id = s.file_id
               WHERE s.owner_username = ?
               ORDER BY s.created_at DESC""",
            (owner_username,),
        ).fetchall()
        return [dict(row) for row in rows]

    def get_drive_share(self, share_id: str, owner_username: Optional[str] = None) -> Optional[Dict[str, Any]]:
        conn = self._conn()
        if owner_username:
            row = conn.execute(
                "SELECT * FROM drive_shares WHERE id = ? AND owner_username = ?",
                (share_id, owner_username),
            ).fetchone()
        else:
            row = conn.execute("SELECT * FROM drive_shares WHERE id = ?", (share_id,)).fetchone()
        return dict(row) if row else None

    def update_drive_share(
        self,
        share_id: str,
        owner_username: str,
        invite_code: Optional[str] = None,
        expires_at: Optional[str] = None,
        max_downloads: Optional[int] = None,
        require_login: bool = False,
    ) -> Optional[Dict[str, Any]]:
        conn = self._conn()
        with conn:
            cur = conn.execute(
                """UPDATE drive_shares
                   SET invite_code = ?, expires_at = ?, max_downloads = ?, require_login = ?
                   WHERE id = ? AND owner_username = ?""",
                (invite_code or None, expires_at or None, max_downloads, 1 if require_login else 0, share_id, owner_username),
            )
            if cur.rowcount <= 0:
                return None
        return self.get_drive_share(share_id, owner_username)

    def delete_drive_share(self, share_id: str, owner_username: str) -> bool:
        conn = self._conn()
        with conn:
            cur = conn.execute(
                "DELETE FROM drive_shares WHERE id = ? AND owner_username = ?",
                (share_id, owner_username),
            )
        return cur.rowcount > 0

    def increment_share_download_count(self, share_id: str) -> None:
        conn = self._conn()
        with conn:
            conn.execute(
                "UPDATE drive_shares SET download_count = download_count + 1 WHERE id = ?",
                (share_id,),
            )

    def log_drive_share_access(self, share_id: str, access_type: str, access_status: str,
                               username: Optional[str] = None,
                               ip_address: Optional[str] = None,
                               user_agent: Optional[str] = None) -> Dict[str, Any]:
        log_id = uuid.uuid4().hex
        timestamp = utcnow_str()
        conn = self._conn()
        with conn:
            conn.execute(
                """INSERT INTO drive_share_access_logs
                   (id, share_id, access_type, access_status, username, ip_address, user_agent, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (log_id, share_id, access_type, access_status, username, ip_address, user_agent, timestamp),
            )
        return {
            "id": log_id,
            "share_id": share_id,
            "access_type": access_type,
            "access_status": access_status,
            "username": username,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "created_at": timestamp,
        }

    def list_drive_share_access_logs(self, share_id: str, owner_username: str, limit: int = 100) -> List[Dict[str, Any]]:
        conn = self._conn()
        rows = conn.execute(
            """SELECT l.*
               FROM drive_share_access_logs l
               JOIN drive_shares s ON s.id = l.share_id
               WHERE l.share_id = ? AND s.owner_username = ?
               ORDER BY l.created_at DESC
               LIMIT ?""",
            (share_id, owner_username, limit),
        ).fetchall()
        return [dict(row) for row in rows]

    def get_user_theme(self, username: str) -> str:
        conn = self._conn()
        row = conn.execute(
            "SELECT theme FROM user_preferences WHERE username = ?",
            (username,),
        ).fetchone()
        if not row or row["theme"] not in {"light", "dark"}:
            return "light"
        return str(row["theme"])

    def set_user_theme(self, username: str, theme: str) -> str:
        if theme not in {"light", "dark"}:
            raise ValueError("仅支持亮色或暗色主题")
        conn = self._conn()
        timestamp = utcnow_str()
        with conn:
            conn.execute(
                """INSERT INTO user_preferences (username, theme, updated_at)
                   VALUES (?, ?, ?)
                   ON CONFLICT(username) DO UPDATE SET
                       theme = excluded.theme,
                       updated_at = excluded.updated_at""",
                (username, theme, timestamp),
            )
        return theme

    # Feedback ---------------------------------------------------------

    def add_feedback(self, username: str, content: str, category: str = "general") -> Dict[str, Any]:
        feedback_id = uuid.uuid4().hex
        timestamp = utcnow_str()
        conn = self._conn()
        with conn:
            conn.execute(
                "INSERT INTO feedback (id, username, content, category, status, created_at) VALUES (?, ?, ?, ?, 'pending', ?)",
                (feedback_id, username, content.strip(), category.strip(), timestamp),
            )
        return {"id": feedback_id, "username": username, "content": content.strip(),
                "category": category, "status": "pending", "created_at": timestamp}

    def list_feedback(self, username: Optional[str] = None, status: Optional[str] = None) -> List[Dict[str, Any]]:
        conn = self._conn()
        clauses = []
        params: list = []
        if username:
            clauses.append("username = ?")
            params.append(username)
        if status:
            clauses.append("status = ?")
            params.append(status)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = conn.execute(f"SELECT * FROM feedback{where} ORDER BY created_at DESC", params).fetchall()
        return [dict(row) for row in rows]

    def reply_feedback(self, feedback_id: str, reply: str) -> None:
        conn = self._conn()
        with conn:
            conn.execute(
                "UPDATE feedback SET admin_reply = ?, replied_at = ?, status = 'replied' WHERE id = ?",
                (reply.strip(), utcnow_str(), feedback_id),
            )

    def close_feedback(self, feedback_id: str) -> None:
        conn = self._conn()
        with conn:
            conn.execute("UPDATE feedback SET status = 'closed' WHERE id = ?", (feedback_id,))

    # ─── User Labels ───

    def remove_user_label(self, username: str, label: str) -> None:
        conn = self._conn()
        with conn:
            conn.execute("DELETE FROM user_labels WHERE username = ? AND label = ?", (username, label))

    def get_user_labels(self, username: str) -> list:
        conn = self._conn()
        rows = conn.execute(
            "SELECT * FROM user_labels WHERE username = ? ORDER BY created_at",
            (username,),
        ).fetchall()
        return [dict(row) for row in rows]

    def add_user_label(self, username: str, label: str, color: str, created_by: str) -> None:
        conn = self._conn()
        label = label.strip()[:50]
        color = color.strip()[:20] if color else "blue"
        if not label:
            raise ValueError("标签名不能为空")
        with conn:
            try:
                conn.execute(
                    "INSERT INTO user_labels (id, username, label, color, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (str(uuid.uuid4()), username, label, color, created_by, utcnow_str()),
                )
            except sqlite3.IntegrityError:
                raise ValueError(f"用户 {username} 已有标签「{label}」")

    def list_all_user_labels(self) -> dict:
        """Returns a dict mapping username -> list of label dicts."""
        conn = self._conn()
        rows = conn.execute("SELECT * FROM user_labels ORDER BY created_at").fetchall()
        result = {}
        for row in rows:
            u = row["username"]
            if u not in result:
                result[u] = []
            result[u].append(dict(row))
        return result
