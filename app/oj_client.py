from __future__ import annotations

import html
import os
import re
from dataclasses import dataclass
from typing import Optional

import requests
from requests import Session
from requests.exceptions import RequestException, SSLError


__all__ = [
    "OJLoginError",
    "OJInvalidCredentials",
    "OJAccountNotFound",
    "OJServiceUnavailable",
    "OnlineJudgeClient",
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

    def authenticate(self, username: str, password: str) -> OJUserInfo:
        session = requests.Session()
        session.headers.update({"User-Agent": "BNDSForum/1.0 (+https://onlinejudge.bnds.cn/)"})

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
            return self._fetch_profile(session, username)

        body = response.text
        if "用户名不存在" in body:
            raise OJAccountNotFound(f"账户 {username} 不存在")
        if "密码错误" in body:
            raise OJInvalidCredentials("密码错误")

        raise OJServiceUnavailable("OJ 登录返回了未预期的响应")

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
