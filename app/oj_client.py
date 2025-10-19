from __future__ import annotations

import html
import os
import re
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

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


class OnlineJudgeClient:
    """Thin wrapper around the BNDS OJ login workflow."""

    LOGIN_PATH = "/site/login"
    PROFILE_PATH = "/user/view"
    _CSRF_RE = re.compile(r'name="_csrf"\s+value="([^"]+)"')
    _TITLE_RE = re.compile(r"<title>(.*?)</title>", re.S)

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
                # The production site currently uses a certificate chain that is
                # not trusted in all environments, so default to False to keep
                # the integration functional unless explicitly overridden.
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
            raise OJInvalidCredentials("密码错误")

        raise OJServiceUnavailable("OJ 登录返回了未预期的响应")

    def authenticate(self, username: str, password: str) -> OJUserInfo:
        session = self._login_session(username, password)
        try:
            return self._fetch_profile(session, username)
        finally:
            session.close()

    def fetch_groups(self, username: str, password: str) -> List[OJGroup]:
        session = self._login_session(username, password)
        try:
            return self._scrape_groups(session)
        finally:
            session.close()

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
        try:
            resp = session.get(
                self._url(f"/group/view?id={group_id}"),
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
        except SSLError as exc:
            raise OJServiceUnavailable("无法建立到 OJ 的安全连接") from exc
        except RequestException as exc:
            raise OJServiceUnavailable(f"加载小组 {group_id} 详情失败") from exc
        if resp.status_code != 200:
            return ([], False)

        soup = BeautifulSoup(resp.text, "html.parser")
        table = None
        for candidate in soup.select("table.table"):
            if candidate.select_one("tbody tr a[href*='/user/view']"):
                table = candidate
                break
        if not table:
            return ([], False)

        members: List[OJGroupMember] = []
        for row in table.select("tbody tr"):
            link = row.select_one("td a[href*='/user/view']")
            if not link:
                continue
            href = link.get("href", "")
            user_id = self._parse_query_param(href, "id")
            if not user_id:
                continue
            real_name = link.get_text(strip=True)
            username, resolved_real_name = self._resolve_user_identity(session, user_id, user_cache)
            if not username:
                continue
            members.append(
                OJGroupMember(
                    username=username,
                    real_name=resolved_real_name or real_name,
                )
            )
        return (members, True)

    def _resolve_user_identity(
        self,
        session: Session,
        user_id: str,
        cache: Dict[str, Tuple[str, str]],
    ) -> Tuple[str, str]:
        if user_id in cache:
            return cache[user_id]
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
            cache[user_id] = ("", "")
            return "", ""
        soup = BeautifulSoup(resp.text, "html.parser")
        username = self._extract_detail_value(soup, "用户名")
        nickname = self._extract_detail_value(soup, "昵称")
        cache[user_id] = (username or "", nickname or "")
        return cache[user_id]

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
