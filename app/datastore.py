from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock, local
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from .oj_client import (
    OJAccountNotFound,
    OJInvalidCredentials,
    OJServiceUnavailable,
    OJUserInfo,
    OnlineJudgeClient,
)


ISO_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
DEFAULT_CATEGORY_TAG = "未分类"
DEFAULT_CLASS_TAG = "未分班"


def utcnow_str() -> str:
    return datetime.now(timezone.utc).strftime(ISO_FORMAT)


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
    constant_tags: List[str] = field(default_factory=list)
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
            "constant_tags": self.constant_tags,
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
        self._logger = logging.getLogger(__name__)
        self._class_sync_lock = RLock()
        self._last_class_sync = 0.0
        self._class_sync_interval = float(os.getenv("OJ_GROUP_SYNC_INTERVAL", 6 * 3600))
        self._class_sync_enabled = os.getenv("OJ_SYNC_GROUPS", "true").lower() not in {"0", "false", "no", "off"}
        self._setup_database()
        self._oj_client = OnlineJudgeClient()

    def _conn(self) -> sqlite3.Connection:
        return self._connection_manager.get_connection()

    def _setup_database(self) -> None:
        if self._setup_complete:
            return
        with self._setup_lock:
            if self._setup_complete:
                return
            conn = self._conn()
            self._ensure_schema(conn)
            self._maybe_migrate_legacy(conn)
            self._sync_constant_tag_catalog(conn)
            self._ensure_tag_defaults(conn)
            self._migrate_post_tag_columns(conn)
            self._ensure_root_node(conn)
            self._bootstrap_admin(conn)
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
                    constant_tags TEXT NOT NULL,
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
                    name TEXT PRIMARY KEY
                );

                CREATE TABLE IF NOT EXISTS class_tags (
                    name TEXT PRIMARY KEY,
                    source TEXT NOT NULL DEFAULT 'manual',
                    external_id TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_class_tags_source ON class_tags(source);
                CREATE UNIQUE INDEX IF NOT EXISTS idx_class_tags_external ON class_tags(external_id) WHERE external_id IS NOT NULL;

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

                CREATE TABLE IF NOT EXISTS constant_tags (
                    name TEXT PRIMARY KEY
                );

                CREATE TABLE IF NOT EXISTS tag_nodes (
                    id TEXT PRIMARY KEY,
                    tag TEXT,
                    parent_id TEXT,
                    FOREIGN KEY(parent_id) REFERENCES tag_nodes(id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_tag_nodes_parent ON tag_nodes(parent_id);
                """
            )
            columns = {
                row["name"]
                for row in conn.execute("PRAGMA table_info(users)")
            }
            if "is_banned" not in columns:
                conn.execute("ALTER TABLE users ADD COLUMN is_banned INTEGER NOT NULL DEFAULT 0")
            post_columns = {
                row["name"]
                for row in conn.execute("PRAGMA table_info(posts)")
            }
            if "category_tag" not in post_columns:
                conn.execute("ALTER TABLE posts ADD COLUMN category_tag TEXT NOT NULL DEFAULT ''")
            if "class_tag" not in post_columns:
                conn.execute("ALTER TABLE posts ADD COLUMN class_tag TEXT NOT NULL DEFAULT ''")

    def _ensure_root_node(self, conn: sqlite3.Connection) -> None:
        with conn:
            conn.execute(
                "INSERT OR IGNORE INTO tag_nodes (id, tag, parent_id) VALUES ('root', NULL, NULL)"
            )
            conn.execute(
                "UPDATE tag_nodes SET tag = NULL, parent_id = NULL WHERE id = 'root'"
            )

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
                    "INSERT OR IGNORE INTO users (username, password_hash, role, constant_tags, real_name) VALUES (?, ?, ?, ?, ?)",
                    (
                        user.get("username"),
                        user.get("password_hash"),
                        user.get("role", "user"),
                        json.dumps(sorted(set(user.get("constant_tags", []))), ensure_ascii=False),
                        user.get("real_name", ""),
                    ),
                )
            for tag in legacy.get("normal_tags", []):
                conn.execute(
                    "INSERT OR IGNORE INTO normal_tags (name) VALUES (?)",
                    (tag,),
                )
            tree = legacy.get("tag_tree")
            if tree:
                conn.execute("DELETE FROM tag_nodes")
                self._write_tag_tree(conn, tree)
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

    def _sync_constant_tag_catalog(self, conn: sqlite3.Connection) -> None:
        with conn:
            existing = {
                row["name"]
                for row in conn.execute("SELECT name FROM constant_tags")
            }
            rows = conn.execute("SELECT constant_tags FROM users").fetchall()
        discovered: Set[str] = set()
        for row in rows:
            for tag in self._deserialize_tags(row["constant_tags"]):
                stripped = tag.strip()
                if stripped:
                    discovered.add(stripped)
        missing = [tag for tag in discovered if tag not in existing]
        if not missing:
            return
        with conn:
            conn.executemany(
                "INSERT OR IGNORE INTO constant_tags (name) VALUES (?)",
                [(tag,) for tag in missing],
            )

    def _write_tag_tree(self, conn: sqlite3.Connection, tree: Dict[str, Any]) -> None:
        nodes = {node.get("id"): node for node in tree.get("nodes", []) if node.get("id")}
        if "root" not in nodes:
            nodes["root"] = {"id": "root", "tag": None, "children": []}
        parents: Dict[str, Optional[str]] = {"root": None}
        for node in nodes.values():
            for child_id in node.get("children", []):
                parents[child_id] = node.get("id")
        visited = set()

        def insert_node(node_id: str) -> None:
            if node_id in visited:
                return
            parent_id = parents.get(node_id)
            if parent_id and parent_id not in visited:
                insert_node(parent_id)
            node = nodes.get(node_id, {"id": node_id, "tag": None, "children": []})
            conn.execute(
                "INSERT OR REPLACE INTO tag_nodes (id, tag, parent_id) VALUES (?, ?, ?)",
                (node_id, node.get("tag"), parent_id),
            )
            visited.add(node_id)
            for child_id in node.get("children", []):
                insert_node(child_id)

        insert_node("root")

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
            item.setdefault("constant_tags", [])
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
                password_hash = generate_password_hash("admin123")
                conn.execute(
                    "INSERT INTO users (username, password_hash, role, constant_tags, real_name) VALUES (?, ?, ?, ?, ?)",
                    ("admin", password_hash, "admin", json.dumps([], ensure_ascii=False), ""),
                )

    # Public API methods --------------------------------------------------

    def list_users(self) -> List[Dict[str, Any]]:
        conn = self._conn()
        rows = conn.execute(
            "SELECT username, password_hash, role, constant_tags, real_name, is_banned FROM users"
        ).fetchall()
        users: List[Dict[str, Any]] = []
        for row in rows:
            users.append(
                {
                    "username": row["username"],
                    "password_hash": row["password_hash"],
                    "role": row["role"],
                    "constant_tags": self._deserialize_tags(row["constant_tags"]),
                    "real_name": row["real_name"],
                    "is_banned": bool(row["is_banned"]),
                }
            )
        return users

    def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        conn = self._conn()
        row = conn.execute(
            "SELECT username, password_hash, role, constant_tags, real_name, is_banned FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        if not row:
            return None
        return {
            "username": row["username"],
            "password_hash": row["password_hash"],
            "role": row["role"],
            "constant_tags": self._deserialize_tags(row["constant_tags"]),
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
            constant_tags=record.get("constant_tags", []),
            real_name=record.get("real_name", ""),
            is_banned=bool(record.get("is_banned", False)),
        )

    def create_user(
        self,
        username: str,
        password: str,
        role: str = "user",
        constant_tags: Optional[Iterable[str]] = None,
        real_name: str = "",
    ) -> User:
        if self.get_user(username):
            raise ValueError("用户已存在")
        prepared_tags = self._normalize_tags(constant_tags)
        conn = self._conn()
        password_hash = generate_password_hash(password)
        with conn:
            conn.execute(
                "INSERT INTO users (username, password_hash, role, constant_tags, real_name) VALUES (?, ?, ?, ?, ?)",
                (
                    username,
                    password_hash,
                    role,
                    json.dumps(prepared_tags, ensure_ascii=False),
                    real_name.strip(),
                ),
            )
        return User(
            username=username,
            password_hash=password_hash,
            role=role,
            constant_tags=prepared_tags,
            real_name=real_name.strip(),
            is_banned=False,
        )

    def update_user_constant_tags(self, username: str, constant_tags: Iterable[str]) -> None:
        conn = self._conn()
        with conn:
            row = conn.execute(
                "SELECT constant_tags FROM users WHERE username = ?",
                (username,),
            ).fetchone()
            if not row:
                raise ValueError("未找到用户")

            previous_tags = set(self._deserialize_tags(row["constant_tags"]))
            tags = self._normalize_tags(constant_tags)
            new_tags = set(tags)

            if new_tags:
                conn.executemany(
                    "INSERT OR IGNORE INTO constant_tags (name) VALUES (?)",
                    [(tag,) for tag in new_tags],
                )

            conn.execute(
                "UPDATE users SET constant_tags = ? WHERE username = ?",
                (json.dumps(tags, ensure_ascii=False), username),
            )

            if previous_tags == new_tags:
                return

            post_rows = conn.execute(
                "SELECT id FROM posts WHERE author = ?",
                (username,),
            ).fetchall()

            for post_row in post_rows:
                post_id = post_row["id"]
                existing_rows = conn.execute(
                    "SELECT tag FROM post_tags WHERE post_id = ?",
                    (post_id,),
                ).fetchall()
                existing_tags = [row["tag"] for row in existing_rows]
                normalized_existing = self._normalize_tags(existing_tags)

                residual_tags = [tag for tag in normalized_existing if tag not in previous_tags]
                final_tags = self._normalize_tags(list(residual_tags) + list(new_tags))

                if final_tags == normalized_existing:
                    continue

                self._replace_post_tags(conn, post_id, final_tags)
                conn.execute(
                    "UPDATE posts SET updated_at = ? WHERE id = ?",
                    (utcnow_str(), post_id),
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
        fallback_to_local = True
        if self._oj_client:
            try:
                remote_user = self._oj_client.authenticate(username, password)
            except OJInvalidCredentials:
                return None
            except (OJAccountNotFound, OJServiceUnavailable):
                pass
            else:
                fallback_to_local = False
                return self._upsert_remote_user(remote_user, password)
        if fallback_to_local:
            return self._verify_local_credentials(username, password)
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
            constant_tags=record.get("constant_tags", []),
            real_name=record.get("real_name", ""),
            is_banned=bool(record.get("is_banned", False)),
        )

    def _upsert_remote_user(self, remote_user: OJUserInfo, password: str) -> User:
        conn = self._conn()
        password_hash = generate_password_hash(password)
        with conn:
            existing = conn.execute(
                "SELECT username, role, constant_tags, real_name, is_banned FROM users WHERE username = ?",
                (remote_user.username,),
            ).fetchone()
            if existing:
                conn.execute(
                    "UPDATE users SET password_hash = ?, real_name = ? WHERE username = ?",
                    (password_hash, remote_user.real_name, remote_user.username),
                )
                constant_tags = self._deserialize_tags(existing["constant_tags"])
                role = existing["role"]
                is_banned = bool(existing["is_banned"])
            else:
                conn.execute(
                    "INSERT INTO users (username, password_hash, role, constant_tags, real_name) VALUES (?, ?, ?, ?, ?)",
                    (
                        remote_user.username,
                        password_hash,
                        "user",
                        json.dumps([], ensure_ascii=False),
                        remote_user.real_name,
                    ),
                )
                constant_tags = []
                role = "user"
                is_banned = False
        return User(
            username=remote_user.username,
            password_hash=password_hash,
            role=role,
            constant_tags=constant_tags,
            real_name=remote_user.real_name,
            is_banned=is_banned,
        )

    # Posts ------------------------------------------------------------

    def list_posts(self) -> List[Dict[str, Any]]:
        conn = self._conn()
        rows = conn.execute(
            """
            SELECT id, author, title, content, created_at, updated_at, category_tag, class_tag
            FROM posts
            ORDER BY created_at DESC
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
            SELECT id, author, title, content, created_at, updated_at, category_tag, class_tag
            FROM posts
            {where}
            ORDER BY created_at DESC
            """,
            params,
        ).fetchall()
        return self._build_posts_from_rows(rows)

    def get_post(self, post_id: str) -> Optional[Dict[str, Any]]:
        conn = self._conn()
        row = conn.execute(
            """
            SELECT id, author, title, content, created_at, updated_at, category_tag, class_tag
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
        extra_tags: Optional[Iterable[str]] = None,
        author_constant_tags: Optional[Iterable[str]] = None,
    ) -> Dict[str, Any]:
        conn = self._conn()
        post_id = uuid.uuid4().hex
        timestamp = utcnow_str()
        category = (category_tag or DEFAULT_CATEGORY_TAG).strip() or DEFAULT_CATEGORY_TAG
        class_value = (class_tag or DEFAULT_CLASS_TAG).strip() or DEFAULT_CLASS_TAG
        all_tags = [category, class_value]
        if extra_tags:
            all_tags.extend(extra_tags)
        if author_constant_tags:
            all_tags.extend(author_constant_tags)
        normalized_tags = self._normalize_tags(all_tags)
        with conn:
            conn.execute(
                """
                INSERT INTO posts (id, author, title, content, created_at, updated_at, category_tag, class_tag)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (post_id, author, title, content, timestamp, timestamp, category, class_value),
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
        }

    def update_post(
        self,
        post_id: str,
        *,
        title: Optional[str] = None,
        content: Optional[str] = None,
        category_tag: Optional[str] = None,
        class_tag: Optional[str] = None,
        extra_tags: Optional[Iterable[str]] = None,
        author_constant_tags: Optional[Iterable[str]] = None,
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
        should_update_tags = extra_tags is not None or category_tag is not None or class_tag is not None or author_constant_tags is not None
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
                extras_existing = [tag for tag in existing.get("tags", []) if tag not in {current_category, current_class}]
                extras = extras_existing
                if extra_tags is not None:
                    extras = list(extra_tags)
                if author_constant_tags is not None:
                    extras = extras + list(author_constant_tags)
                normalized_tags = self._normalize_tags([new_category, new_class, *extras])
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
            SELECT p.id, p.author, p.title, p.content, p.created_at, p.updated_at, p.category_tag, p.class_tag, pf.created_at AS favorited_at
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

    # Normal tags ------------------------------------------------------

    def list_normal_tags(self) -> List[str]:
        return self.list_category_tags()

    def list_category_tags(self) -> List[str]:
        conn = self._conn()
        rows = conn.execute("SELECT name FROM normal_tags ORDER BY name").fetchall()
        return [row["name"] for row in rows]

    # Constant tags ---------------------------------------------------

    def list_constant_tags(self) -> List[str]:
        conn = self._conn()
        rows = conn.execute("SELECT name FROM constant_tags ORDER BY name").fetchall()
        return [row["name"] for row in rows]

    def add_constant_tag(self, tag: str) -> bool:
        name = (tag or "").strip()
        if not name:
            raise ValueError("标签名称不能为空")
        conn = self._conn()
        with conn:
            result = conn.execute(
                "INSERT OR IGNORE INTO constant_tags (name) VALUES (?)",
                (name,),
            )
        return result.rowcount > 0

    def remove_constant_tag(self, tag: str) -> None:
        name = (tag or "").strip()
        if not name:
            raise ValueError("未指定标签")
        conn = self._conn()
        with conn:
            rows = conn.execute("SELECT username, constant_tags FROM users").fetchall()
            conn.execute("DELETE FROM constant_tags WHERE name = ?", (name,))
        updates: List[tuple[str, List[str]]] = []
        for row in rows:
            tags = self._deserialize_tags(row["constant_tags"])
            if name not in tags:
                continue
            remaining = [item for item in tags if item != name]
            updates.append((row["username"], remaining))
        for username, remaining in updates:
            self.update_user_constant_tags(username, remaining)

    def _ensure_category_exists(self, conn: sqlite3.Connection, tag: str) -> None:
        name = (tag or "").strip()
        if not name:
            return
        conn.execute("INSERT OR IGNORE INTO normal_tags (name) VALUES (?)", (name,))

    def _ensure_class_exists(self, conn: sqlite3.Connection, tag: str, *, source: str = "manual", external_id: str | None = None) -> None:
        name = (tag or "").strip()
        if not name:
            return
        conn.execute(
            "INSERT OR IGNORE INTO class_tags (name, source, external_id) VALUES (?, ?, ?)",
            (name, source, external_id),
        )

    def _ensure_tag_defaults(self, conn: sqlite3.Connection) -> None:
        with conn:
            self._ensure_category_exists(conn, DEFAULT_CATEGORY_TAG)
            existing_normal = {
                row["name"]
                for row in conn.execute("SELECT name FROM normal_tags")
            }
            if not existing_normal:
                self._ensure_category_exists(conn, DEFAULT_CATEGORY_TAG)
            self._ensure_class_exists(conn, DEFAULT_CLASS_TAG, source="builtin", external_id=None)
            existing_classes = {
                row["name"]
                for row in conn.execute("SELECT name FROM class_tags")
            }
            if not existing_classes:
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

    def add_normal_tag(self, tag: str) -> None:
        self.add_category_tag(tag)

    def add_category_tag(self, tag: str) -> None:
        conn = self._conn()
        with conn:
            conn.execute("INSERT OR IGNORE INTO normal_tags (name) VALUES (?)", (tag,))

    def remove_normal_tag(self, tag: str) -> None:
        self.remove_category_tag(tag)

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
        if auto_sync and self._class_sync_enabled:
            self._maybe_sync_class_tags()
        conn = self._conn()
        rows = conn.execute(
            "SELECT name, source, external_id FROM class_tags ORDER BY source, name"
        ).fetchall()
        if with_meta:
            return [
                {
                    "name": row["name"],
                    "source": row["source"] if "source" in row.keys() else "manual",
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

    def remove_class_tag(self, tag: str) -> None:
        name = (tag or "").strip()
        if not name:
            raise ValueError("未指定班级标签")
        conn = self._conn()
        with conn:
            affected_posts = [row["id"] for row in conn.execute("SELECT id FROM posts WHERE class_tag = ?", (name,))]
            self._ensure_class_exists(conn, DEFAULT_CLASS_TAG)
            conn.execute("DELETE FROM class_tags WHERE name = ?", (name,))
            conn.execute("UPDATE posts SET class_tag = ? WHERE class_tag = ?", (DEFAULT_CLASS_TAG, name))
            for post_id in affected_posts:
                tag_rows = conn.execute("SELECT tag FROM post_tags WHERE post_id = ?", (post_id,)).fetchall()
                tags = [DEFAULT_CLASS_TAG] + [row["tag"] for row in tag_rows if row["tag"] != name]
                self._replace_post_tags(conn, post_id, self._normalize_tags(tags))

    def _maybe_sync_class_tags(self) -> None:
        now = time.time()
        if now - self._last_class_sync < self._class_sync_interval:
            return
        with self._class_sync_lock:
            if now - self._last_class_sync < self._class_sync_interval:
                return
            try:
                self.sync_class_tags_from_oj()
            except OJServiceUnavailable as exc:
                self._logger.debug("skip class tag sync: %s", exc)
            finally:
                self._last_class_sync = time.time()

    def sync_class_tags_from_oj(self) -> Dict[str, int]:
        groups = self._oj_client.fetch_groups()
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
        with conn:
            for group in groups:
                gid = str(group.get("id") or "").strip() or None
                name = str(group.get("name") or "").strip()
                if not name:
                    continue
                if name in existing_by_name and existing_by_name[name]["source"] not in {"oj", "builtin"}:
                    # 保留手动创建的同名标签，避免覆盖管理员数据。
                    continue
                if gid and gid in existing_by_ext:
                    current = existing_by_ext[gid]
                    if current["name"] != name:
                        conn.execute("DELETE FROM class_tags WHERE name = ?", (current["name"],))
                        added += 1
                    else:
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
                if gid:
                    seen_ext.add(gid)
            stale = [
                row["name"]
                for row in existing_rows
                if row["source"] == "oj" and row["external_id"] and row["external_id"] not in seen_ext
            ]
            if stale:
                removed = len(stale)
                conn.executemany("DELETE FROM class_tags WHERE name = ?", [(name,) for name in stale])
        return {"added": added, "updated": updated, "removed": removed}

    # Tag tree ---------------------------------------------------------

    def get_tag_tree(self) -> Dict[str, Any]:
        conn = self._conn()
        rows = conn.execute(
            "SELECT id, tag, parent_id, rowid FROM tag_nodes ORDER BY rowid"
        ).fetchall()
        nodes: Dict[str, Dict[str, Any]] = {}
        children: Dict[str, List[str]] = {}
        for row in rows:
            node_id = row["id"]
            nodes[node_id] = {
                "id": node_id,
                "tag": row["tag"],
                "children": [],
            }
            children.setdefault(node_id, [])
        for row in rows:
            parent_id = row["parent_id"]
            node_id = row["id"]
            if parent_id:
                children.setdefault(parent_id, []).append(node_id)
        for node_id, node in nodes.items():
            node["children"] = children.get(node_id, [])
        return {"nodes": list(nodes.values())}

    def save_tag_tree(self, tree: Dict[str, Any]) -> None:
        conn = self._conn()
        nodes = {node.get("id"): node for node in tree.get("nodes", []) if node.get("id")}
        if "root" not in nodes:
            raise ValueError("树必须包含根节点")
        with conn:
            conn.execute("DELETE FROM tag_nodes")
            self._write_tag_tree(conn, tree)

    def add_tree_node(self, parent_id: str, tag: Optional[str]) -> Dict[str, Any]:
        conn = self._conn()
        node_id = uuid.uuid4().hex
        with conn:
            parent_exists = conn.execute(
                "SELECT 1 FROM tag_nodes WHERE id = ?",
                (parent_id,),
            ).fetchone()
            if not parent_exists:
                raise ValueError("父节点不存在")
            conn.execute(
                "INSERT INTO tag_nodes (id, tag, parent_id) VALUES (?, ?, ?)",
                (node_id, tag, parent_id),
            )
        return {"id": node_id, "tag": tag, "children": []}

    def update_tree_node(self, node_id: str, *, tag: Optional[str] = None) -> None:
        conn = self._conn()
        with conn:
            if node_id == "root":
                conn.execute("UPDATE tag_nodes SET tag = NULL WHERE id = 'root'")
                return
            updated = conn.execute(
                "UPDATE tag_nodes SET tag = ? WHERE id = ?",
                (tag, node_id),
            )
            if updated.rowcount == 0:
                raise ValueError("节点不存在")

    def remove_tree_node(self, node_id: str) -> None:
        if node_id == "root":
            raise ValueError("不能删除根节点")
        conn = self._conn()
        with conn:
            deleted = conn.execute("DELETE FROM tag_nodes WHERE id = ?", (node_id,))
            if deleted.rowcount == 0:
                raise ValueError("节点不存在")

    # Query helpers ----------------------------------------------------

    def posts_with_tags(self, required_tags: Iterable[str]) -> List[Dict[str, Any]]:
        tags = self._normalize_tags(required_tags)
        if not tags:
            return self.list_posts()
        conn = self._conn()
        placeholders = ",".join(["?"] * len(tags))
        rows = conn.execute(
            f"""
            SELECT p.id, p.author, p.title, p.content, p.created_at, p.updated_at, p.category_tag, p.class_tag
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

    def user_has_post_with_tags(self, username: str, required_tags: Iterable[str]) -> bool:
        tags = self._normalize_tags(required_tags)
        conn = self._conn()
        if not tags:
            result = conn.execute(
                "SELECT 1 FROM posts WHERE author = ? LIMIT 1",
                (username,),
            ).fetchone()
            return result is not None
        placeholders = ",".join(["?"] * len(tags))
        result = conn.execute(
            f"""
            SELECT 1
            FROM posts p
            JOIN post_tags pt ON p.id = pt.post_id
            WHERE p.author = ? AND pt.tag IN ({placeholders})
            GROUP BY p.id
            HAVING COUNT(DISTINCT pt.tag) = ?
            LIMIT 1
            """,
            (username, *tags, len(tags)),
        ).fetchone()
        return result is not None

    # Internal helpers -------------------------------------------------

    def _replace_post_tags(self, conn: sqlite3.Connection, post_id: str, tags: Sequence[str]) -> None:
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
                }
            )
        return posts

    def _load_tags_for_posts(self, conn: sqlite3.Connection, post_ids: Sequence[str]) -> Dict[str, List[str]]:
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

    def _load_comments_for_posts(self, conn: sqlite3.Connection, post_ids: Sequence[str]) -> Dict[str, List[Dict[str, Any]]]:
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

    def _load_favorite_counts(self, conn: sqlite3.Connection, post_ids: Sequence[str]) -> Dict[str, int]:
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
