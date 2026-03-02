from __future__ import annotations

import html
import os
import re
import time
from urllib.parse import urlparse
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Set

import requests
from bs4 import BeautifulSoup
from requests import Session
from requests.exceptions import RequestException, SSLError


__all__ = [
    "OJLoginError",
    "OJInvalidCredentials",
    "OJAccountNotFound",
    "OJServiceUnavailable",
    "OnlineJudgeClient",
    "OJGroup",
    "OJGroupMember",
    "OJUserInfo",
]


class OJLoginError(Exception):
    """Base error for OJ login failures."""


class OJInvalidCredentials(OJLoginError):
    """The username exists, but the password is incorrect."""


class OJAccountNotFound(OJLoginError):
    """The requested user does not exist on the OJ."""


class OJServiceUnavailable(OJLoginError):
    """The remote service is unreachable or returned an unexpected response."""


@dataclass
class OJUserInfo:
    username: str
    real_name: str


@dataclass
class OJGroupMember:
    username: str
    real_name: str


@dataclass
class OJGroup:
    tag: str
    display_name: str
    members: List[OJGroupMember]
    memberships_complete: bool = True
    external_id: Optional[str] = None


class OnlineJudgeClient:
    """Thin wrapper around the BNDS OJ login workflow."""

    LOGIN_PATH = "/site/login"
    PROFILE_PATH = "/user/view"
    _CSRF_RE = re.compile(r'name="_csrf"\s+value="([^"]+)"')
    _TITLE_RE = re.compile(r"<title>(.*?)</title>", re.S)
    _GROUP_LINK_RE = re.compile(r"/group/(?:index|view)?/?(\d+)[^>]*>([^<]+)<", re.I)
    _LOGIN_FORM_RE = re.compile(r"LoginForm\[username\]|LoginForm\[password\]", re.I)

    def __init__(
        self,
        base_url: Optional[str] = None,
        *,
        timeout: float = 10.0,
        verify_ssl: Optional[bool] = None,
    ):
        self.base_url = (base_url or os.getenv("OJ_BASE_URL", "https://onlinejudge.bnds.cn")).rstrip("/")
        self.timeout = float(os.getenv("OJ_TIMEOUT", timeout))

        if verify_ssl is None:
            env = os.getenv("OJ_VERIFY_SSL")
            if env is None:
                verify_ssl = False
            else:
                verify_ssl = env.lower() in {"1", "true", "yes", "on"}
        self.verify_ssl = verify_ssl

        if not self.verify_ssl:
            from urllib3 import disable_warnings
            from urllib3.exceptions import InsecureRequestWarning

            disable_warnings(InsecureRequestWarning)

    def _build_session(self) -> Session:
        session = requests.Session()
        session.headers.update({"User-Agent": "BNDSForum/1.0 (+https://onlinejudge.bnds.cn/)"})
        return session

    def _login_session(self, username: str, password: str) -> Session:
        session = self._build_session()
        try:
            login_page = session.get(
                self._url(self.LOGIN_PATH),
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
        except SSLError as exc:
            raise OJServiceUnavailable("无法建立到 OJ 的安全连接") from exc
        except RequestException as exc:
            raise OJServiceUnavailable("连接 OJ 登录页失败") from exc

        csrf_token = self._extract_csrf(login_page.text)
        if not csrf_token:
            raise OJServiceUnavailable("登录页缺少 CSRF 信息")

        try:
            response = session.post(
                self._url(self.LOGIN_PATH),
                data={
                    "_csrf": csrf_token,
                    "LoginForm[username]": username,
                    "LoginForm[password]": password,
                    "LoginForm[rememberMe]": "0",
                },
                timeout=self.timeout,
                allow_redirects=False,
                verify=self.verify_ssl,
            )
        except SSLError as exc:
            raise OJServiceUnavailable("无法建立到 OJ 的安全连接") from exc
        except RequestException as exc:
            raise OJServiceUnavailable("发送登录请求失败") from exc

        if response.status_code == 302:
            return session

        body = response.text
        if "用户名不存在" in body:
            raise OJAccountNotFound(f"账户 {username} 不存在")
        if "密码错误" in body:
            print('Request Failed')
            raise OJInvalidCredentials("密码错误")

        raise OJServiceUnavailable("OJ 登录返回了未预期的响应")

    def authenticate(self, username: str, password: str) -> OJUserInfo:
        session = self._login_session(username, password)
        try:
            return self._fetch_profile(session, username)
        finally:
            session.close()

    def authenticate_with_cookie(self, username: str, phpsessid: str) -> OJUserInfo:
        session = self._session_with_cookie(phpsessid)
        try:
            return self._fetch_profile(session, username)
        finally:
            session.close()

    def resolve_username_from_cookie(self, phpsessid: str) -> Optional[str]:
        if not phpsessid:
            return None
        session = self._session_with_cookie(phpsessid)
        try:
            profile_href = self._locate_profile_link(session)
            if not profile_href:
                return None
            return self._scrape_username_from_profile(session, profile_href)
        finally:
            session.close()

    def fetch_groups(self, username: str, password: str) -> List[OJGroup]:
        session = self._login_session(username, password)
        try:
            return self._scrape_groups(session)
        finally:
            session.close()

    def fetch_groups_with_cookie(self, phpsessid: str) -> List[OJGroup]:
        session = self._session_with_cookie(phpsessid)
        try:
            return self._scrape_groups(session)
        finally:
            session.close()

    def fetch_groups_public(self) -> List[OJGroup]:
        """
        获取公开可见的小组列表（不含成员），使用与旧实现一致的页面解析。
        """
        try:
            response = requests.get(
                self._url("/group/index"),
                timeout=self.timeout,
                verify=self.verify_ssl,
                headers={"User-Agent": "BNDSForum/1.0 (+https://onlinejudge.bnds.cn/)"},
            )
        except SSLError as exc:
            raise OJServiceUnavailable("无法建立到 OJ 的安全连接") from exc
        except RequestException as exc:
            raise OJServiceUnavailable("获取小组列表失败") from exc

        if response.status_code != 200:
            raise OJServiceUnavailable(f"OJ 返回 {response.status_code}，无法获取小组列表")

        groups: List[OJGroup] = []
        seen_ids = set()
        for group_id, name in self._GROUP_LINK_RE.findall(response.text):
            if group_id in seen_ids:
                continue
            cleaned = html.unescape(name).strip()
            if not cleaned:
                continue
            seen_ids.add(group_id)
            groups.append(
                OJGroup(
                    tag=cleaned,
                    display_name=cleaned,
                    members=[],
                    memberships_complete=False,
                    external_id=group_id,
                )
            )

        if not groups:
            raise OJServiceUnavailable("未能从 OJ 页面解析出小组信息")

        return groups

    def _fetch_profile(self, session: Session, username: str) -> OJUserInfo:
        try:
            profile_resp = session.get(
                self._url(self.PROFILE_PATH),
                params={"name": username},
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
        except SSLError as exc:
            raise OJServiceUnavailable("无法建立到 OJ 的安全连接") from exc
        except RequestException as exc:
            raise OJServiceUnavailable("获取 OJ 用户资料失败") from exc

        if profile_resp.status_code == 404:
            raise OJServiceUnavailable("OJ 返回 404，无法获取用户资料")
        if self._is_login_page(profile_resp.text) or profile_resp.url.endswith(self.LOGIN_PATH):
            raise OJInvalidCredentials("Cookie 或登录状态已失效")

        real_name = self._extract_title(profile_resp.text) or username
        return OJUserInfo(username=username, real_name=real_name.strip() or username)

    def _extract_csrf(self, html_text: str) -> Optional[str]:
        match = self._CSRF_RE.search(html_text)
        if not match:
            return None
        return match.group(1)

    def _extract_title(self, html_text: str) -> Optional[str]:
        match = self._TITLE_RE.search(html_text)
        if not match:
            return None
        return html.unescape(match.group(1)).strip()

    def _url(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            return path
        return f"{self.base_url}{path}"

    def _session_with_cookie(self, phpsessid: str) -> Session:
        session = self._build_session()
        domain = urlparse(self.base_url).hostname or "onlinejudge.bnds.cn"
        session.cookies.set("PHPSESSID", phpsessid, domain=domain)
        return session

    def _is_login_page(self, html_text: str) -> bool:
        if not html_text:
            return False
        return bool(self._LOGIN_FORM_RE.search(html_text))

    def _scrape_groups(self, session: Session) -> List[OJGroup]:
        try:
            index_resp = session.get(
                self._url("/group/index"),
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
        except SSLError as exc:
            raise OJServiceUnavailable("无法建立到 OJ 的安全连接") from exc
        except RequestException as exc:
            raise OJServiceUnavailable("拉取小组列表失败") from exc
        if index_resp.status_code != 200:
            raise OJServiceUnavailable("无法获取小组列表页面")
        if self._is_login_page(index_resp.text) or index_resp.url.endswith(self.LOGIN_PATH):
            raise OJInvalidCredentials("需要登录才能访问小组列表")

        soup = BeautifulSoup(index_resp.text, "html.parser")
        groups: List[Tuple[str, str]] = []
        for card in soup.select("div[data-key] .card-header a[href*='/group/view']"):
            href = card.get("href", "")
            group_id = self._parse_query_param(href, "id")
            if not group_id:
                continue
            name = card.get_text(strip=True)
            if not name:
                continue
            groups.append((group_id, html.unescape(name)))

        if not groups:
            return []

        user_cache: Dict[str, Tuple[str, str]] = {}
        result: List[OJGroup] = []
        for index, (group_id, group_name) in enumerate(groups):
            members, complete = self._scrape_group_members(session, group_id, user_cache)
            display = group_name.strip()
            tag = display
            result.append(
                OJGroup(
                    tag=tag,
                    display_name=display,
                    members=members,
                    memberships_complete=complete,
                    external_id=group_id,
                )
            )
            if index + 1 < len(groups):
                time.sleep(0.25)
        return result

    def _scrape_group_members(
        self,
        session: Session,
        group_id: str,
        user_cache: Dict[str, Tuple[str, str]],
    ) -> Tuple[List[OJGroupMember], bool]:
        members: List[OJGroupMember] = []
        seen_usernames: Set[str] = set()
        page = 1
        per_page = 50
        success = False

        while True:
            params = {"id": group_id, "per-page": per_page}
            if page > 1:
                params["page"] = page
            try:
                resp = session.get(
                    self._url("/group/view"),
                    params=params,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                )
            except SSLError as exc:
                raise OJServiceUnavailable("无法建立到 OJ 的安全连接") from exc
            except RequestException as exc:
                raise OJServiceUnavailable(f"加载小组 {group_id} 详情失败") from exc
            if resp.status_code != 200:
                break

            soup = BeautifulSoup(resp.text, "html.parser")
            table = None
            for candidate in soup.select("table.table"):
                if candidate.select_one("tbody tr a[href*='/user/view']"):
                    table = candidate
                    break
            if not table:
                if page == 1:
                    return ([], False)
                break

            rows = table.select("tbody tr")
            if not rows:
                break

            new_entries = 0
            for row in rows:
                link = row.select_one("td a[href*='/user/view']")
                if not link:
                    continue
                href = link.get("href", "")
                user_id = self._parse_query_param(href, "id")
                if not user_id:
                    continue
                real_name = link.get_text(strip=True)
                username, resolved_real_name = self._resolve_user_identity(session, user_id, user_cache)
                if not username or username in seen_usernames:
                    continue
                seen_usernames.add(username)
                members.append(
                    OJGroupMember(
                        username=username,
                        real_name=resolved_real_name or real_name,
                    )
                )
                new_entries += 1

            if new_entries:
                success = True

            if len(rows) < per_page or new_entries == 0:
                break

            page += 1
            time.sleep(0.2)

        return (members, success)

    def _scrape_username_from_profile(self, session: Session, href: str) -> Optional[str]:
        target = self._url(href)
        try:
            resp = session.get(target, timeout=self.timeout, verify=self.verify_ssl)
        except SSLError as exc:
            raise OJServiceUnavailable("无法建立到 OJ 的安全连接") from exc
        except RequestException:
            return None
        if resp.status_code != 200 or self._is_login_page(resp.text):
            return None
        soup = BeautifulSoup(resp.text, "html.parser")
        cell = soup.select_one("#w0 > tbody > tr:nth-child(1) > td")
        if cell:
            text = cell.get_text(strip=True)
            if text:
                return text
        for row in soup.select("#w0 tr"):
            header = row.select_one("th")
            value = row.select_one("td")
            if not header or not value:
                continue
            if header.get_text(strip=True) == "用户名":
                text = value.get_text(strip=True)
                if text:
                    return text
        return None

    def _locate_profile_link(self, session: Session) -> Optional[str]:
        candidate_paths = ["/", "/site/index", "/user/index"]
        for path in candidate_paths:
            try:
                resp = session.get(self._url(path), timeout=self.timeout, verify=self.verify_ssl)
            except SSLError:
                continue
            except RequestException:
                continue
            if resp.status_code != 200 or self._is_login_page(resp.text):
                continue
            soup = BeautifulSoup(resp.text, "html.parser")
            anchor = soup.select_one("#w1 > li:nth-child(1) > a[href]")
            if not anchor:
                continue
            href = anchor.get("href", "").strip()
            if href:
                return href
        return None

    def _resolve_user_identity(
        self,
        session: Session,
        user_id: str,
        user_cache: Dict[str, Tuple[str, str]],
    ) -> Tuple[str | None, str]:
        if user_id in user_cache:
            return user_cache[user_id]
        try:
            resp = session.get(
                self._url(f"/user/view?id={user_id}"),
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
        except SSLError as exc:
            raise OJServiceUnavailable("无法建立到 OJ 的安全连接") from exc
        except RequestException as exc:
            raise OJServiceUnavailable(f"加载用户 {user_id} 信息失败") from exc
        if resp.status_code != 200:
            user_cache[user_id] = ("", "")
            return "", ""
        soup = BeautifulSoup(resp.text, "html.parser")
        username = self._extract_detail_value(soup, "用户名")
        nickname = self._extract_detail_value(soup, "昵称")
        user_cache[user_id] = (username or "", nickname or "")
        return user_cache[user_id]

    def _extract_detail_value(self, soup: BeautifulSoup, label: str) -> Optional[str]:
        header = soup.find("th", string=label)
        if not header:
            return None
        cell = header.find_next("td")
        if not cell:
            return None
        return cell.get_text(strip=True)

    def _parse_query_param(self, href: str, key: str) -> Optional[str]:
        if "?" not in href:
            return None
        query = href.split("?", 1)[1]
        for part in query.split("&"):
            if "=" not in part:
                continue
            name, value = part.split("=", 1)
            if name == key:
                return value
        return None
