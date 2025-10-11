from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from typing import Any, Dict, Iterable, List, Optional

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash


ISO_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"


def utcnow_str() -> str:
    return datetime.now(timezone.utc).strftime(ISO_FORMAT)


class JsonDocument:
    def __init__(self, path: Path, default_factory):
        self.path = path
        self.default_factory = default_factory
        self._lock = RLock()
        self._ensure_exists()

    def _ensure_exists(self) -> None:
        if not self.path.exists():
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("w", encoding="utf-8") as handle:
                json.dump(self.default_factory(), handle, ensure_ascii=False, indent=2)

    def read(self):
        with self._lock:
            self._ensure_exists()
            with self.path.open("r", encoding="utf-8") as handle:
                return json.load(handle)

    def write(self, payload) -> None:
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("w", encoding="utf-8") as handle:
                json.dump(payload, handle, ensure_ascii=False, indent=2)


@dataclass
class User(UserMixin):
    username: str
    password_hash: str
    role: str = "user"
    constant_tags: List[str] = field(default_factory=list)
    real_name: str = ""

    def get_id(self) -> str:
        return self.username

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    def to_record(self) -> Dict[str, Any]:
        return {
            "username": self.username,
            "password_hash": self.password_hash,
            "role": self.role,
            "constant_tags": self.constant_tags,
            "real_name": self.real_name,
        }


class DataStore:
    def __init__(self, base_path: Path):
        self.base_path = base_path
        self.users_doc = JsonDocument(self.base_path / "users.json", lambda: [])
        self.posts_doc = JsonDocument(self.base_path / "posts.json", lambda: [])
        self.tags_doc = JsonDocument(self.base_path / "tags.json", lambda: {"normal_tags": []})
        self.tag_tree_doc = JsonDocument(
            self.base_path / "tag_tree.json",
            lambda: {
                "nodes": [
                    {
                        "id": "root",
                        "tag": None,
                        "children": [],
                    }
                ]
            },
        )
        self._bootstrap_admin()

    # User management -------------------------------------------------
    def _bootstrap_admin(self) -> None:
        users = self.users_doc.read()
        if not users:
            admin_password = generate_password_hash("admin123")
            admin = User(username="admin", password_hash=admin_password, role="admin")
            self.users_doc.write([admin.to_record()])

    def list_users(self) -> List[Dict[str, Any]]:
        users = self.users_doc.read()
        for item in users:
            item.setdefault("constant_tags", [])
            item.setdefault("real_name", "")
        return users

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
        )

    def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        for record in self.users_doc.read():
            if record["username"] == username:
                record.setdefault("constant_tags", [])
                record.setdefault("real_name", "")
                return record
        return None

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
        record = User(
            username=username,
            password_hash=generate_password_hash(password),
            role=role,
            constant_tags=list(constant_tags or []),
            real_name=real_name.strip(),
        )
        users = self.users_doc.read()
        users.append(record.to_record())
        self.users_doc.write(users)
        return record

    def update_user_constant_tags(self, username: str, constant_tags: Iterable[str]) -> None:
        users = self.users_doc.read()
        for item in users:
            if item["username"] == username:
                item["constant_tags"] = list(constant_tags)
                self.users_doc.write(users)
                return
        raise ValueError("未找到用户")

    def set_user_role(self, username: str, role: str) -> None:
        users = self.users_doc.read()
        for item in users:
            if item["username"] == username:
                item["role"] = role
                self.users_doc.write(users)
                return
        raise ValueError("未找到用户")

    def verify_user(self, username: str, password: str) -> Optional[User]:
        record = self.get_user(username)
        if not record:
            return None
        if check_password_hash(record["password_hash"], password):
            return User(
                username=record["username"],
                password_hash=record["password_hash"],
                role=record.get("role", "user"),
                constant_tags=record.get("constant_tags", []),
                real_name=record.get("real_name", ""),
            )
        return None

    def update_user_real_name(self, username: str, real_name: str) -> None:
        users = self.users_doc.read()
        for item in users:
            if item["username"] == username:
                item["real_name"] = real_name.strip()
                self.users_doc.write(users)
                return
        raise ValueError("未找到用户")

    # Posts -----------------------------------------------------------
    def list_posts(self) -> List[Dict[str, Any]]:
        posts = self.posts_doc.read()
        return sorted(posts, key=lambda item: item.get("created_at", ""), reverse=True)

    def get_post(self, post_id: str) -> Optional[Dict[str, Any]]:
        for post in self.posts_doc.read():
            if post["id"] == post_id:
                return post
        return None

    def create_post(self, author: str, title: str, content: str, tags: Iterable[str]) -> Dict[str, Any]:
        posts = self.posts_doc.read()
        post = {
            "id": uuid.uuid4().hex,
            "author": author,
            "title": title,
            "content": content,
            "tags": sorted(list(set(tags))),
            "created_at": utcnow_str(),
            "updated_at": utcnow_str(),
            "comments": [],
        }
        posts.append(post)
        self.posts_doc.write(posts)
        return post

    def update_post(
        self,
        post_id: str,
        *,
        title: Optional[str] = None,
        content: Optional[str] = None,
        tags: Optional[Iterable[str]] = None,
    ) -> Dict[str, Any]:
        posts = self.posts_doc.read()
        for post in posts:
            if post["id"] == post_id:
                if title is not None:
                    post["title"] = title
                if content is not None:
                    post["content"] = content
                if tags is not None:
                    post["tags"] = sorted(list(set(tags)))
                post["updated_at"] = utcnow_str()
                self.posts_doc.write(posts)
                return post
        raise ValueError("未找到文章")

    def delete_post(self, post_id: str) -> None:
        posts = self.posts_doc.read()
        filtered = [post for post in posts if post["id"] != post_id]
        if len(posts) == len(filtered):
            raise ValueError("未找到文章")
        self.posts_doc.write(filtered)

    def add_comment(self, post_id: str, author: str, content: str) -> Dict[str, Any]:
        posts = self.posts_doc.read()
        for post in posts:
            if post["id"] == post_id:
                comment = {
                    "id": uuid.uuid4().hex,
                    "author": author,
                    "content": content,
                    "created_at": utcnow_str(),
                }
                post.setdefault("comments", []).append(comment)
                post["updated_at"] = utcnow_str()
                self.posts_doc.write(posts)
                return comment
        raise ValueError("未找到文章")

    # Normal tags -----------------------------------------------------
    def list_normal_tags(self) -> List[str]:
        payload = self.tags_doc.read()
        return sorted(payload.get("normal_tags", []))

    def add_normal_tag(self, tag: str) -> None:
        payload = self.tags_doc.read()
        normal_tags = set(payload.get("normal_tags", []))
        normal_tags.add(tag)
        payload["normal_tags"] = sorted(normal_tags)
        self.tags_doc.write(payload)

    def remove_normal_tag(self, tag: str) -> None:
        payload = self.tags_doc.read()
        normal_tags = [item for item in payload.get("normal_tags", []) if item != tag]
        payload["normal_tags"] = normal_tags
        self.tags_doc.write(payload)

    # Tag tree --------------------------------------------------------
    def get_tag_tree(self) -> Dict[str, Any]:
        return self.tag_tree_doc.read()

    def save_tag_tree(self, tree: Dict[str, Any]) -> None:
        self.tag_tree_doc.write(tree)

    def add_tree_node(self, parent_id: str, tag: Optional[str]) -> Dict[str, Any]:
        tree = self.tag_tree_doc.read()
        node_id = uuid.uuid4().hex
        new_node = {"id": node_id, "tag": tag, "children": []}
        found = False
        for node in tree["nodes"]:
            if node["id"] == parent_id:
                node.setdefault("children", []).append(node_id)
                found = True
                break
        if not found:
            raise ValueError("父节点不存在")
        tree["nodes"].append(new_node)
        self.tag_tree_doc.write(tree)
        return new_node

    def update_tree_node(self, node_id: str, *, tag: Optional[str] = None) -> None:
        tree = self.tag_tree_doc.read()
        for node in tree["nodes"]:
            if node["id"] == node_id:
                node["tag"] = tag
                self.tag_tree_doc.write(tree)
                return
        raise ValueError("节点不存在")

    def remove_tree_node(self, node_id: str) -> None:
        if node_id == "root":
            raise ValueError("不能删除根节点")
        tree = self.tag_tree_doc.read()
        nodes = {node["id"]: node for node in tree["nodes"]}
        if node_id not in nodes:
            raise ValueError("节点不存在")
        # Remove references
        for node in tree["nodes"]:
            node["children"] = [child for child in node.get("children", []) if child != node_id]
        # Remove subtree
        def collect_ids(target_id: str) -> List[str]:
            result = [target_id]
            for child_id in nodes.get(target_id, {}).get("children", []):
                result.extend(collect_ids(child_id))
            return result

        to_remove = set(collect_ids(node_id))
        tree["nodes"] = [node for node in tree["nodes"] if node["id"] not in to_remove]
        self.tag_tree_doc.write(tree)

    # Query helpers ---------------------------------------------------
    def posts_with_tags(self, required_tags: Iterable[str]) -> List[Dict[str, Any]]:
        required = set(required_tags)
        return [post for post in self.list_posts() if required.issubset(set(post.get("tags", [])))]

    def user_has_post_with_tags(self, username: str, required_tags: Iterable[str]) -> bool:
        required = set(required_tags)
        for post in self.list_posts():
            if post.get("author") == username and required.issubset(set(post.get("tags", []))):
                return True
        return False
