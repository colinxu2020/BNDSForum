from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock, local
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Literal, cast

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


def utcnow_str() -> str:
    return datetime.now(timezone.utc).strftime(ISO_FORMAT)


MessagePreference = Literal["notify", "silent", "block"]
MESSAGE_PREFERENCE_DEFAULT: MessagePreference = "notify"
MESSAGE_PREFERENCES: Set[MessagePreference] = {"notify", "silent", "block"}


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
        self._setup_database()
        self._oj_client = OnlineJudgeClient()

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
            self._sync_constant_tag_catalog(conn)
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
                    FOREIGN KEY(author) REFERENCES users(username) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_posts_author ON posts(author);
                CREATE INDEX IF NOT EXISTS idx_posts_created_at ON posts(created_at);

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

                CREATE TABLE IF NOT EXISTS message_preferences (
                    owner TEXT NOT NULL,
                    other_user TEXT NOT NULL,
                    preference TEXT NOT NULL CHECK (preference IN ('notify','silent','block')),
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (owner, other_user),
                    FOREIGN KEY(owner) REFERENCES users(username) ON DELETE CASCADE,
                    FOREIGN KEY(other_user) REFERENCES users(username) ON DELETE CASCADE
                );
                """
            )
            columns = {
                row["name"]
                for row in conn.execute("PRAGMA table_info(users)")
            }
            if "is_banned" not in columns:
                conn.execute("ALTER TABLE users ADD COLUMN is_banned INTEGER NOT NULL DEFAULT 0")

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
            "SELECT id, author, title, content, created_at, updated_at FROM posts ORDER BY created_at DESC"
        ).fetchall()
        return self._build_posts_from_rows(rows)

    def get_post(self, post_id: str) -> Optional[Dict[str, Any]]:
        conn = self._conn()
        row = conn.execute(
            "SELECT id, author, title, content, created_at, updated_at FROM posts WHERE id = ?",
            (post_id,),
        ).fetchone()
        if not row:
            return None
        return self._build_posts_from_rows([row])[0]

    def create_post(self, author: str, title: str, content: str, tags: Iterable[str]) -> Dict[str, Any]:
        conn = self._conn()
        post_id = uuid.uuid4().hex
        timestamp = utcnow_str()
        normalized_tags = self._normalize_tags(tags)
        with conn:
            conn.execute(
                "INSERT INTO posts (id, author, title, content, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                (post_id, author, title, content, timestamp, timestamp),
            )
            self._replace_post_tags(conn, post_id, normalized_tags)
        return self.get_post(post_id) or {
            "id": post_id,
            "author": author,
            "title": title,
            "content": content,
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
        tags: Optional[Iterable[str]] = None,
    ) -> Dict[str, Any]:
        conn = self._conn()
        updates: List[str] = []
        params: List[Any] = []
        if title is not None:
            updates.append("title = ?")
            params.append(title)
        if content is not None:
            updates.append("content = ?")
            params.append(content)
        should_touch = bool(updates) or tags is not None
        if should_touch:
            updates.append("updated_at = ?")
            params.append(utcnow_str())
        params.append(post_id)
        with conn:
            if updates:
                conn.execute(f"UPDATE posts SET {', '.join(updates)} WHERE id = ?", params)
            if tags is not None:
                normalized_tags = self._normalize_tags(tags)
                self._replace_post_tags(conn, post_id, normalized_tags)
        updated = self.get_post(post_id)
        if updated is None:
            raise ValueError("未找到文章")
        return updated

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
            SELECT p.id, p.author, p.title, p.content, p.created_at, p.updated_at, pf.created_at AS favorited_at
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

    def _message_row_to_dict(self, row: sqlite3.Row) -> Dict[str, Any]:
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
        preference = self.get_message_preference(recipient, sender)
        if preference == "block":
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

    def add_normal_tag(self, tag: str) -> None:
        conn = self._conn()
        with conn:
            conn.execute("INSERT OR IGNORE INTO normal_tags (name) VALUES (?)", (tag,))

    def remove_normal_tag(self, tag: str) -> None:
        conn = self._conn()
        with conn:
            conn.execute("DELETE FROM normal_tags WHERE name = ?", (tag,))

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
            SELECT p.id, p.author, p.title, p.content, p.created_at, p.updated_at
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
