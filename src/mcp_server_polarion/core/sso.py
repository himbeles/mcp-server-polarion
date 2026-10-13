"""Browser-owned SSO session; credentials remain in memory."""

from __future__ import annotations

import asyncio
import logging
from contextlib import suppress
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from mcp_server_polarion.core.config import PolarionConfig
from mcp_server_polarion.core.exceptions import PolarionAuthError

if TYPE_CHECKING:
    from playwright.async_api import BrowserContext, Playwright

logger = logging.getLogger(__name__)
TOKEN_SCRIPT = """() => {
    const owner = typeof window.getRestApiToken === 'function' ? window : window.top;
    return typeof owner.getRestApiToken === 'function' ? owner.getRestApiToken() : null;
}"""  # noqa: S105


class PolarionSsoSession:
    """Keep browser alive; renew login when Polarion rejects session."""

    def __init__(self, config: PolarionConfig) -> None:
        self.config = config
        self._playwright: Playwright | None = None
        self._context: BrowserContext | None = None
        self._token: str | None = None

    async def start(self) -> None:
        if self._context is not None:
            return
        try:
            from playwright.async_api import async_playwright  # noqa: PLC0415
        except ImportError:
            raise PolarionAuthError(
                "SSO requires optional dependency: mcp-server-polarion[sso]",
                status_code=0,
            ) from None
        try:
            self._playwright = await async_playwright().start()
            executable = self.config.polarion_sso_browser_executable
            self._context = await self._playwright.chromium.launch_persistent_context(
                str(self.config.polarion_sso_profile_dir.expanduser()),
                headless=self.config.polarion_sso_headless,
                ignore_https_errors=not self.config.polarion_verify_ssl,
                executable_path=str(executable) if executable else None,
                channel=None
                if executable
                else self.config.polarion_sso_browser_channel,
            )
            await self.authenticate()
        except Exception:
            await self.close()
            raise PolarionAuthError(
                "SSO browser startup/login failed. Check browser installation, "
                "corporate policy, and SSO settings; use POLARION_SSO_HEADLESS=false "
                "for interactive login/MFA.",
                status_code=0,
            ) from None

    async def _read_token(self) -> str | None:
        from playwright.async_api import Error  # noqa: PLC0415

        if self._context is None:
            return None
        origin = urlsplit(self.config.polarion_url)
        for page in self._context.pages:
            for frame in page.frames:
                location = urlsplit(frame.url)
                if (location.scheme, location.netloc) != (origin.scheme, origin.netloc):
                    continue
                try:
                    token: object = await frame.evaluate(TOKEN_SCRIPT)
                    if isinstance(token, str) and token.strip():
                        return token
                except Error:
                    continue
        return None

    async def authenticate(self) -> None:
        from playwright.async_api import Error  # noqa: PLC0415

        if self._context is None:
            raise PolarionAuthError("SSO browser is not running", status_code=0)
        self._token = None
        logger.info("Authenticating browser session through configured SSO URL")
        page = (
            self._context.pages[0]
            if self._context.pages
            else await self._context.new_page()
        )
        with suppress(Error):
            # Redirect/navigation may still complete while polling.
            await page.goto(
                self.config.sso_login_url,
                wait_until="domcontentloaded",
                timeout=self.config.polarion_sso_timeout * 1000,
            )
        deadline = asyncio.get_running_loop().time() + self.config.polarion_sso_timeout
        while asyncio.get_running_loop().time() < deadline:
            self._token = await self._read_token()
            if self._token:
                logger.info("Polarion browser session authenticated")
                return
            await asyncio.sleep(0.5)
        raise PolarionAuthError(
            "SSO timed out. Use POLARION_SSO_HEADLESS=false for login/MFA; ensure "
            "the SSO landing page exposes getRestApiToken().",
            status_code=0,
        )

    async def headers(self, url: str, *, refresh: bool = False) -> dict[str, str]:
        origin, target = urlsplit(self.config.polarion_url), urlsplit(url)
        if (target.scheme, target.netloc) != (origin.scheme, origin.netloc):
            raise PolarionAuthError(
                "Refusing to send SSO credentials to another origin", status_code=0
            )
        started = self._context is None
        await self.start()
        if refresh and not started:
            await self.authenticate()
        elif not started:
            token = await self._read_token()
            if token:
                self._token = token
            else:
                await self.authenticate()
        assert self._context is not None  # noqa: S101
        cookies = await self._context.cookies([url])
        return {
            "X-Polarion-REST-Token": self._token or "",
            "Cookie": "; ".join(f"{c['name']}={c['value']}" for c in cookies),
        }

    async def close(self) -> None:
        try:
            if self._context is not None:
                await self._context.close()
        finally:
            self._context = None
            self._token = None
            if self._playwright is not None:
                await self._playwright.stop()
                self._playwright = None
