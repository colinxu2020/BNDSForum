#!/usr/bin/env python3
"""
性能压力测试脚本
================

该脚本针对 BNDSForum Flask 服务器执行多场景性能测试，涵盖：

- 匿名访问首页、标签树、文章详情等读取操作
- 登录流程、文章创建与编辑、发表评论等写入操作
- 管理后台各类页面访问

脚本会在测试前自动备份 SQLite 数据库，并在测试结束或发生异常时恢复，
以确保测试过程中产生的数据不会污染现有环境。
"""

from __future__ import annotations

import argparse
import html
import os
import random
import re
import shutil
import statistics
import string
import threading
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

import requests
from requests import Session


POST_LINK_RE = re.compile(
    r'href="(?P<url>/post/(?P<id>[0-9a-f]+))">\s*(?P<title>.*?)\s*</a>',
    re.IGNORECASE | re.DOTALL,
)


@dataclass
class PostRecord:
    post_id: str
    title: str
    content: str


@dataclass
class Operation:
    name: str
    func: Callable[["Worker"], bool]
    weight: int
    description: str


class SharedState:
    """线程安全的共享测试数据池"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._posts: Dict[str, PostRecord] = {}
        self._post_ids: List[str] = []

    def add_post(self, post_id: str, title: str, content: str) -> None:
        with self._lock:
            if post_id not in self._posts:
                self._post_ids.append(post_id)
            self._posts[post_id] = PostRecord(post_id=post_id, title=title, content=content)

    def update_post(self, post_id: str, title: Optional[str] = None, content: Optional[str] = None) -> None:
        with self._lock:
            record = self._posts.get(post_id)
            if not record:
                return
            if title is not None:
                record.title = title
            if content is not None:
                record.content = content

    def get_random_post(self) -> Optional[PostRecord]:
        with self._lock:
            if not self._post_ids:
                return None
            post_id = random.choice(self._post_ids)
            record = self._posts.get(post_id)
            if record is None:
                return None
            # 返回副本避免外部修改内部状态
            return PostRecord(post_id=record.post_id, title=record.title, content=record.content)

    def absorb_posts(self, posts: Iterable[PostRecord]) -> None:
        for post in posts:
            self.add_post(post.post_id, post.title, post.content)

    def count(self) -> int:
        with self._lock:
            return len(self._post_ids)


class MetricsCollector:
    """集中记录每个操作的耗时、成功率及错误信息"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._durations: Dict[str, List[float]] = defaultdict(list)
        self._success: Dict[str, int] = defaultdict(int)
        self._failures: Dict[str, int] = defaultdict(int)
        self._last_error: Dict[str, str] = {}

    def record(self, name: str, duration: float, success: bool, error: Optional[str] = None) -> None:
        with self._lock:
            self._durations[name].append(duration)
            if success:
                self._success[name] += 1
            else:
                self._failures[name] += 1
                if error:
                    self._last_error[name] = error

    def report(self, total_duration: float) -> List[Dict[str, object]]:
        results: List[Dict[str, object]] = []
        for name, durations in sorted(self._durations.items()):
            count = len(durations)
            successes = self._success.get(name, 0)
            failures = self._failures.get(name, 0)
            success_rate = (successes / count) * 100 if count else 0.0
            avg = statistics.mean(durations) if durations else 0.0
            minimum = min(durations) if durations else 0.0
            maximum = max(durations) if durations else 0.0
            median = statistics.median(durations) if durations else 0.0
            p95 = self._percentile(durations, 95) if durations else 0.0
            tps = count / total_duration if total_duration > 0 else 0.0
            results.append(
                {
                    "name": name,
                    "count": count,
                    "success_rate": success_rate,
                    "avg": avg,
                    "median": median,
                    "p95": p95,
                    "min": minimum,
                    "max": maximum,
                    "tps": tps,
                    "successes": successes,
                    "failures": failures,
                    "last_error": self._last_error.get(name),
                }
            )
        return results

    @staticmethod
    def _percentile(values: Sequence[float], percentile: float) -> float:
        if not values:
            return 0.0
        sorted_vals = sorted(values)
        k = (len(sorted_vals) - 1) * (percentile / 100)
        f = int(k)
        c = min(f + 1, len(sorted_vals) - 1)
        if f == c:
            return sorted_vals[f]
        d0 = sorted_vals[f] * (c - k)
        d1 = sorted_vals[c] * (k - f)
        return d0 + d1


class Worker:
    """执行具体操作的工作线程"""

    def __init__(self, tester: "PerformanceTest", worker_id: int) -> None:
        self.tester = tester
        self.worker_id = worker_id
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": f"BNDSForumPerfTest/1.0 worker/{worker_id}"})
        self.logged_in = False

    def ensure_logged_in(self) -> None:
        if not self.logged_in:
            if not self.tester.login(self.session):
                raise RuntimeError("无法完成登录流程")
            self.logged_in = True


class PerformanceTest:
    """整体测试协调器"""

    def __init__(self, args: argparse.Namespace) -> None:
        self.base_url = args.base_url.rstrip("/")
        self.username = args.username
        self.password = args.password
        self.duration = args.duration
        self.concurrency = args.concurrency
        self.timeout = args.timeout
        self.seed_posts = args.seed_posts
        self.db_path = Path(args.db_path)
        self.backup_path: Optional[Path] = None
        self._backup_entries: List[Tuple[Path, Path]] = []
        self.metrics = MetricsCollector()
        self.shared_state = SharedState()
        self._rng = random.Random(args.seed)
        self.operations: List[Operation] = self._build_operations()

    def backup_database(self) -> None:
        if not self.db_path.exists():
            raise FileNotFoundError(f"数据库不存在：{self.db_path}")
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        self._backup_entries = []

        def _copy_with_suffix(source: Path) -> Optional[Path]:
            backup_name = f"{source.name}.perf-backup-{timestamp}"
            backup_path = source.parent / backup_name
            shutil.copy2(source, backup_path)
            self._backup_entries.append((source, backup_path))
            return backup_path

        self.backup_path = _copy_with_suffix(self.db_path)

        for sidecar in self._journal_sidecar_paths():
            if sidecar.exists():
                _copy_with_suffix(sidecar)

        if not self.backup_path:
            raise RuntimeError("备份数据库失败：未能创建主数据库备份文件")

        backed_files = ", ".join(str(entry[1]) for entry in self._backup_entries)
        print(f"[备份] 数据库及关联文件已备份到 {backed_files}")

    def restore_database(self) -> None:
        if not self._backup_entries:
            print("[警告] 未找到备份文件，无法还原数据库")
            return

        for original, backup in self._backup_entries:
            if backup.exists():
                shutil.copy2(backup, original)
                print(f"[还原] {original.name} 已从 {backup.name} 恢复")
            elif original.exists():
                original.unlink()
                print(f"[还原] 已删除 {original.name}（对应备份缺失）")

        backed_originals = {original for original, _ in self._backup_entries}
        for sidecar in self._journal_sidecar_paths():
            if sidecar not in backed_originals and sidecar.exists():
                sidecar.unlink()
                print(f"[还原] 已移除过期文件 {sidecar.name}")

    def _journal_sidecar_paths(self) -> List[Path]:
        base_name = self.db_path.name
        return [
            self.db_path.with_name(f"{base_name}-wal"),
            self.db_path.with_name(f"{base_name}-shm"),
        ]

    def _build_operations(self) -> List[Operation]:
        return [
            Operation("view_index", self.op_view_index, weight=4, description="访问首页"),
            Operation("view_tags", self.op_view_tags, weight=2, description="访问标签树"),
            Operation("view_post_detail", self.op_view_post_detail, weight=4, description="查看文章详情"),
            Operation("login_flow", self.op_login_flow, weight=2, description="完整登录流程"),
            Operation("create_post", self.op_create_post, weight=3, description="创建新文章"),
            Operation("add_comment", self.op_add_comment, weight=3, description="发表评论"),
            Operation("edit_post", self.op_edit_post, weight=2, description="编辑既有文章"),
            Operation("admin_dashboard", self.op_admin_dashboard, weight=1, description="访问管理后台"),
            Operation("admin_user_list", self.op_admin_user_list, weight=1, description="访问用户管理"),
        ]

    # --- 准备与辅助逻辑 -------------------------------------------------

    def prepare(self) -> None:
        print("[准备] 验证服务器可用性...")
        with requests.Session() as session:
            resp = session.get(f"{self.base_url}/", timeout=self.timeout)
            resp.raise_for_status()
        print("[准备] 预加载现有文章...")
        with requests.Session() as preload_session:
            preload_session.headers.update({"User-Agent": "BNDSForumPerfTest/seed"})
            existing_posts = self._fetch_posts_from_index(preload_session)
            self.shared_state.absorb_posts(existing_posts)
        print(f"[准备] 已记录现有文章 {len(existing_posts)} 篇")

        print(f"[准备] 生成基准文章 {self.seed_posts} 篇")
        with requests.Session() as seed_session:
            if not self.login(seed_session):
                raise RuntimeError("种子数据初始化：管理员登录失败")
            for _ in range(self.seed_posts):
                title, content = self._generate_post_payload()
                post_id = self._create_post_internal(seed_session, title, content)
                if post_id:
                    self.shared_state.add_post(post_id, title, content)
        print(f"[准备] 种子文章总计：{self.shared_state.count()} 篇")

    def login(self, session: Session) -> bool:
        login_page = session.get(f"{self.base_url}/auth/login", timeout=self.timeout)
        if login_page.status_code != 200:
            return False
        resp = session.post(
            f"{self.base_url}/auth/login",
            data={"username": self.username, "password": self.password},
            allow_redirects=True,
            timeout=self.timeout,
        )
        if resp.status_code != 200:
            return False
        text = resp.text
        return "登录成功" in text or "退出（" in text

    def _fetch_posts_from_index(self, session: Session, html_source: Optional[str] = None) -> List[PostRecord]:
        if html_source is None:
            resp = session.get(f"{self.base_url}/", timeout=self.timeout)
            if resp.status_code != 200:
                return []
            html_source = resp.text
        posts: List[PostRecord] = []
        for match in POST_LINK_RE.finditer(html_source):
            raw_title = match.group("title")
            title = html.unescape(raw_title.strip())
            post_id = match.group("id")
            posts.append(PostRecord(post_id=post_id, title=title, content=""))
        return posts

    def _generate_post_payload(self) -> Tuple[str, str]:
        random_suffix = uuid.uuid4().hex[:8]
        title = f"性能测试文章 {random_suffix}"
        paragraphs = []
        for _ in range(3):
            body = "".join(self._rng.choice(string.ascii_letters + " ") for _ in range(160))
            paragraphs.append(body.strip())
        content = "\n\n".join(f"段落 {_ + 1}: {para}" for _, para in enumerate(paragraphs))
        return title, content

    def _create_post_internal(self, session: Session, title: str, content: str) -> Optional[str]:
        resp = session.post(
            f"{self.base_url}/post/new",
            data={"title": title, "content": content},
            allow_redirects=True,
            timeout=self.timeout,
        )
        if resp.status_code != 200:
            return None
        post_id = self._extract_post_id_by_title(session, resp.text, title)
        if not post_id:
            # 回退到重新抓取首页
            post_id = self._extract_post_id_by_title(session, None, title)
        return post_id

    def _extract_post_id_by_title(self, session: Session, html_source: Optional[str], title: str) -> Optional[str]:
        posts = self._fetch_posts_from_index(session, html_source)
        for post in posts:
            if post.title == title:
                return post.post_id
        return None

    # --- 操作定义 -----------------------------------------------------

    def op_view_index(self, worker: Worker) -> bool:
        resp = worker.session.get(f"{self.base_url}/", timeout=self.timeout)
        return resp.status_code == 200 and "最新文章" in resp.text

    def op_view_tags(self, worker: Worker) -> bool:
        resp = worker.session.get(f"{self.base_url}/tags/", timeout=self.timeout)
        return resp.status_code == 200 and "标签" in resp.text

    def op_view_post_detail(self, worker: Worker) -> bool:
        post = self.shared_state.get_random_post()
        if not post:
            return False
        resp = worker.session.get(f"{self.base_url}/post/{post.post_id}", timeout=self.timeout)
        return resp.status_code == 200

    def op_login_flow(self, worker: Worker) -> bool:
        with requests.Session() as session:
            session.headers.update({"User-Agent": f"BNDSForumPerfTest/login/{worker.worker_id}"})
            login_page = session.get(f"{self.base_url}/auth/login", timeout=self.timeout)
            if login_page.status_code != 200:
                return False
            resp = session.post(
                f"{self.base_url}/auth/login",
                data={"username": self.username, "password": self.password},
                timeout=self.timeout,
                allow_redirects=True,
            )
            if resp.status_code != 200:
                return False
            return "退出（" in resp.text or "登录成功" in resp.text

    def op_create_post(self, worker: Worker) -> bool:
        worker.ensure_logged_in()
        title, content = self._generate_post_payload()
        resp = worker.session.post(
            f"{self.base_url}/post/new",
            data={"title": title, "content": content},
            timeout=self.timeout,
            allow_redirects=True,
        )
        if resp.status_code != 200:
            return False
        post_id = self._extract_post_id_by_title(worker.session, resp.text, title)
        if not post_id:
            post_id = self._extract_post_id_by_title(worker.session, None, title)
        if not post_id:
            return False
        self.shared_state.add_post(post_id, title, content)
        return True

    def op_add_comment(self, worker: Worker) -> bool:
        worker.ensure_logged_in()
        post = self.shared_state.get_random_post()
        if not post:
            return False
        comment = f"性能测试评论 {uuid.uuid4().hex[:6]}"
        resp = worker.session.post(
            f"{self.base_url}/post/{post.post_id}",
            data={"content": comment},
            timeout=self.timeout,
            allow_redirects=True,
        )
        if resp.status_code != 200:
            return False
        return "评论已发布" in resp.text or comment in resp.text

    def op_edit_post(self, worker: Worker) -> bool:
        worker.ensure_logged_in()
        post = self.shared_state.get_random_post()
        if not post:
            return False
        new_title = f"{post.title} · 编辑 {uuid.uuid4().hex[:4]}"
        new_content = post.content or f"更新内容 {uuid.uuid4().hex}"
        resp = worker.session.post(
            f"{self.base_url}/post/{post.post_id}/edit",
            data={"title": new_title, "content": new_content},
            timeout=self.timeout,
            allow_redirects=True,
        )
        if resp.status_code != 200:
            return False
        if "文章已更新" in resp.text:
            self.shared_state.update_post(post.post_id, new_title, new_content)
            return True
        # 直接返回 200 也判为成功
        self.shared_state.update_post(post.post_id, new_title, new_content)
        return True

    def op_admin_dashboard(self, worker: Worker) -> bool:
        worker.ensure_logged_in()
        resp = worker.session.get(f"{self.base_url}/admin/", timeout=self.timeout)
        return resp.status_code == 200 and "管理后台" in resp.text

    def op_admin_user_list(self, worker: Worker) -> bool:
        worker.ensure_logged_in()
        resp = worker.session.get(f"{self.base_url}/admin/users", timeout=self.timeout)
        return resp.status_code == 200 and "用户管理" in resp.text

    # --- 主执行逻辑 ---------------------------------------------------

    def run(self) -> float:
        print("[执行] 启动性能测试...")
        start = time.perf_counter()
        end_time = start + self.duration
        workers = [Worker(self, i) for i in range(self.concurrency)]
        threads: List[threading.Thread] = []

        for worker in workers:
            thread = threading.Thread(target=self._worker_loop, args=(worker, end_time), daemon=False)
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        total = time.perf_counter() - start
        print(f"[执行] 完成，耗时 {total:.2f} 秒")
        return total

    def _worker_loop(self, worker: Worker, end_time: float) -> None:
        while time.perf_counter() < end_time:
            operation = self._select_operation()
            op_start = time.perf_counter()
            success = False
            error_message: Optional[str] = None
            try:
                success = operation.func(worker)
                if not success and error_message is None:
                    error_message = "操作返回失败"
            except Exception as exc:  # pylint: disable=broad-except
                success = False
                error_message = repr(exc)
            duration = time.perf_counter() - op_start
            self.metrics.record(operation.name, duration, success, error_message if not success else None)

    def _select_operation(self) -> Operation:
        weights = [op.weight for op in self.operations]
        return self._rng.choices(self.operations, weights=weights, k=1)[0]

    # --- 结果展示 -----------------------------------------------------

    def print_report(self, total_duration: float) -> None:
        print("\n[报告] 操作指标汇总（耗时单位：秒）")
        print(
            f"{'操作':<22}{'样本':>6}{'成功率':>9}{'TPS':>9}"
            f"{'avg':>10}{'p95':>10}{'median':>10}{'min':>10}{'max':>10}"
        )
        print("-" * 96)
        for record in self.metrics.report(total_duration):
            count = record["count"]
            success_rate = record["success_rate"]
            tps = record["tps"]
            avg = record["avg"]
            p95 = record["p95"]
            median = record["median"]
            minimum = record["min"]
            maximum = record["max"]
            name = record["name"]
            print(
                f"{name:<22}{count:>6}{success_rate:>8.1f}%{tps:>9.2f}"
                f"{avg:>10.4f}{p95:>10.4f}{median:>10.4f}{minimum:>10.4f}{maximum:>10.4f}"
            )
            if record["failures"]:
                error = record.get("last_error")
                if error:
                    print(f"  ↳ 最近错误: {error}")


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="BNDSForum 服务器性能测试工具")
    parser.add_argument("--base-url", default="http://localhost:6001", help="目标服务器地址（默认：http://localhost:6001）")
    parser.add_argument("--username", default=os.getenv("PERF_USERNAME", "admin"), help="登录用户名")
    parser.add_argument("--password", default=os.getenv("PERF_PASSWORD", "admin123"), help="登录密码")
    parser.add_argument("--db-path", default="data/forum.sqlite3", help="SQLite 数据库路径")
    parser.add_argument("--duration", type=float, default=30.0, help="压力测试持续时间（秒）")
    parser.add_argument("--concurrency", type=int, default=4, help="并发工作线程数量")
    parser.add_argument("--timeout", type=float, default=10.0, help="单次请求超时时间（秒）")
    parser.add_argument("--seed-posts", type=int, default=2, help="测试前额外生成的种子文章数")
    parser.add_argument("--seed", type=int, default=None, help="随机数种子，便于复现")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> None:
    args = parse_args(argv)
    random.seed(args.seed)
    tester = PerformanceTest(args)
    tester.backup_database()
    total_duration = 0.0
    try:
        tester.prepare()
        total_duration = tester.run()
    finally:
        tester.restore_database()
    tester.print_report(total_duration)


if __name__ == "__main__":
    main()
