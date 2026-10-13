"""SSO session lifecycle and retry contracts without real credentials."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import respx
from playwright.async_api import Error
from pydantic import ValidationError

from mcp_server_polarion.core.client import PolarionClient
from mcp_server_polarion.core.config import PolarionConfig
from mcp_server_polarion.core.exceptions import PolarionAuthError, PolarionError
from mcp_server_polarion.core.sso import PolarionSsoSession

BASE = "https://polarion.example.com/polarion/rest/v1"


def config(**kwargs):
    return PolarionConfig(
        polarion_url="https://polarion.example.com",
        polarion_auth_mode="sso",
        _env_file=None,
        **kwargs,
    )


def browser_session():
    session = PolarionSsoSession(config())
    frame = MagicMock(url="https://polarion.example.com/polarion/")
    frame.evaluate = AsyncMock(return_value="session-token")
    page = MagicMock(frames=[frame])
    page.goto = AsyncMock()
    context = MagicMock(pages=[page])
    context.cookies = AsyncMock(return_value=[{"name": "session", "value": "cookie"}])
    context.close = AsyncMock()
    session._context = context
    return session, context, frame


def test_sso_config_without_pat():
    cfg = config()
    assert cfg.sso_login_url.endswith("/polarion/ssoLogin/Single-Sign-On")
    assert cfg.polarion_sso_headless


@pytest.mark.parametrize(
    "url", ["https://other.example.com/login", "http://polarion.example.com/login"]
)
def test_sso_rejects_foreign_login(url):
    with pytest.raises(ValidationError):
        config(polarion_sso_url=url)


async def test_matching_cookies_and_token_refresh():
    session, context, frame = browser_session()
    result = await session.headers(BASE + "/projects")
    assert result == {
        "X-Polarion-REST-Token": "session-token",
        "Cookie": "session=cookie",
    }
    context.cookies.assert_awaited_once_with([BASE + "/projects"])
    frame.evaluate.return_value = "new-token"
    assert (await session.headers(BASE))["X-Polarion-REST-Token"] == "new-token"


async def test_foreign_api_origin_rejected():
    session, _, _ = browser_session()
    with pytest.raises(PolarionAuthError, match="another origin"):
        await session.headers("https://other.example.com/")


async def test_missing_token_and_forced_refresh_navigate_sso():
    session, context, frame = browser_session()
    frame.evaluate.side_effect = [None, "renewed-token", "forced-token"]
    assert (await session.headers(BASE))["X-Polarion-REST-Token"] == "renewed-token"
    assert (await session.headers(BASE, refresh=True))[
        "X-Polarion-REST-Token"
    ] == "forced-token"
    assert context.pages[0].goto.await_count == 2


async def test_read_token_ignores_foreign_frames_and_navigation_errors():
    session, context, frame = browser_session()
    foreign = MagicMock(url="https://idp.example.com/")
    frame.evaluate.side_effect = Error("navigation")
    context.pages[0].frames = [foreign, frame]
    assert await session._read_token() is None
    foreign.evaluate.assert_not_called()
    session._context = None
    assert await session._read_token() is None


async def test_auth_without_context():
    with pytest.raises(PolarionAuthError, match="not running"):
        await PolarionSsoSession(config()).authenticate()


async def test_timeout_and_navigation_error_are_safe():
    session, context, frame = browser_session()
    session.config.polarion_sso_timeout = 0.001
    context.pages[0].goto.side_effect = Error("secret redirect URL")
    frame.evaluate.return_value = None
    with pytest.raises(PolarionAuthError, match="timed out"):
        await session.authenticate()


async def test_start_and_close_browser():
    session = PolarionSsoSession(config())
    frame = MagicMock(url="https://polarion.example.com/polarion/")
    frame.evaluate = AsyncMock(return_value="token")
    page = MagicMock(frames=[frame], goto=AsyncMock())
    context = MagicMock(
        pages=[page], close=AsyncMock(), cookies=AsyncMock(return_value=[])
    )
    playwright = MagicMock(stop=AsyncMock())
    playwright.chromium.launch_persistent_context = AsyncMock(return_value=context)
    manager = MagicMock(start=AsyncMock(return_value=playwright))
    with patch("playwright.async_api.async_playwright", return_value=manager):
        await session.headers(BASE, refresh=True)
        await session.start()
    kwargs = playwright.chromium.launch_persistent_context.call_args.kwargs
    assert kwargs["channel"] == "msedge" and kwargs["headless"] is True
    await session.close()
    context.close.assert_awaited_once()
    playwright.stop.assert_awaited_once()
    assert session._token is None
    await session.close()


async def test_start_failure_sanitizes_errors():
    session = PolarionSsoSession(config())
    playwright = MagicMock(stop=AsyncMock())
    playwright.chromium.launch_persistent_context = AsyncMock(
        side_effect=Error("secret")
    )
    manager = MagicMock(start=AsyncMock(return_value=playwright))
    with (
        patch("playwright.async_api.async_playwright", return_value=manager),
        pytest.raises(PolarionAuthError) as caught,
    ):
        await session.start()
    assert "secret" not in str(caught.value)
    playwright.stop.assert_awaited_once()


@pytest.mark.parametrize("method", ["GET", "POST", "PATCH"])
async def test_client_renews_rejected_session_once(method):
    with respx.mock(base_url=BASE) as mock:
        route = mock.route(method=method, url=BASE + "/projects").mock(
            side_effect=[httpx.Response(401), httpx.Response(200, json={"data": []})]
        )
        async with PolarionClient(config(), write_delay=0, min_interval=0) as client:
            assert client._sso is not None
            client._sso.headers = AsyncMock(
                side_effect=[
                    {"X-Polarion-REST-Token": "old", "Cookie": "s=old"},
                    {"X-Polarion-REST-Token": "new", "Cookie": "s=new"},
                ]
            )
            result = await client._request(method, "/projects")
            assert result == {"data": []}
            assert client._sso.headers.call_args.kwargs == {"refresh": True}
        assert route.call_count == 2
        assert route.calls.last.request.headers["x-polarion-rest-token"] == "new"
        assert "authorization" not in route.calls.last.request.headers


@pytest.mark.parametrize("status,count", [(401, 2), (403, 1)])
async def test_client_auth_retry_is_bounded_and_403_is_not_retried(status, count):
    with respx.mock(base_url=BASE) as mock:
        route = mock.get("/projects").mock(return_value=httpx.Response(status))
        async with PolarionClient(config(), min_interval=0) as client:
            client._sso.headers = AsyncMock(return_value={"X-Polarion-REST-Token": "t"})
            with pytest.raises(PolarionAuthError):
                await client.get("/projects")
        assert route.call_count == count


async def test_redirect_reauth_and_stream_reauth():
    with respx.mock(base_url=BASE) as mock:
        route = mock.get("/projects").mock(
            side_effect=[
                httpx.Response(302, headers={"Location": "https://idp.example.com/"}),
                httpx.Response(200, json={"data": []}),
                httpx.Response(401),
                httpx.Response(200, content=b"file"),
            ]
        )
        async with PolarionClient(config(), min_interval=0) as client:
            client._sso.headers = AsyncMock(return_value={"X-Polarion-REST-Token": "t"})
            await client.get("/projects")
            assert await client.get_bytes("/projects", max_bytes=10) == b"file"
        assert route.call_count == 4


async def test_stream_retry_bounded():
    with respx.mock(base_url=BASE) as mock:
        route = mock.get("/projects").mock(return_value=httpx.Response(401))
        async with PolarionClient(config(), min_interval=0) as client:
            client._sso.headers = AsyncMock(return_value={"X-Polarion-REST-Token": "t"})
            with pytest.raises(PolarionAuthError):
                await client.get_bytes("/projects", max_bytes=10)
        assert route.call_count == 2


async def test_non_json_response_has_clear_error():
    with respx.mock(base_url=BASE) as mock:
        mock.get("/projects").mock(
            return_value=httpx.Response(200, text="<html>login</html>")
        )
        async with PolarionClient(config(), min_interval=0) as client:
            client._sso.headers = AsyncMock(return_value={"X-Polarion-REST-Token": "t"})
            with pytest.raises(PolarionError, match="Expected JSON"):
                await client.get("/projects")


async def test_client_rejects_absolute_paths():
    async with PolarionClient(config()) as client:
        with pytest.raises(PolarionAuthError, match="relative API path"):
            await client.get("https://other.example.com")


async def test_custom_executable_and_new_page():

    session = PolarionSsoSession(
        config(polarion_sso_browser_executable=Path("/browser"))
    )
    frame = MagicMock(url="https://polarion.example.com/polarion/")
    frame.evaluate = AsyncMock(return_value="token")
    page = MagicMock(frames=[frame], goto=AsyncMock())
    context = MagicMock(pages=[], close=AsyncMock())

    async def new_page():
        context.pages.append(page)
        return page

    context.new_page = new_page
    playwright = MagicMock(stop=AsyncMock())
    playwright.chromium.launch_persistent_context = AsyncMock(return_value=context)
    manager = MagicMock(start=AsyncMock(return_value=playwright))
    with patch("playwright.async_api.async_playwright", return_value=manager):
        await session.start()
    kwargs = playwright.chromium.launch_persistent_context.call_args.kwargs
    assert kwargs["executable_path"] == "/browser" and kwargs["channel"] is None
    await session.close()


async def test_missing_optional_dependency(monkeypatch):

    monkeypatch.setitem(sys.modules, "playwright.async_api", None)
    with pytest.raises(PolarionAuthError, match="optional dependency"):
        await PolarionSsoSession(config()).start()


async def test_close_stops_playwright_if_context_close_fails():
    session, context, _ = browser_session()
    playwright = MagicMock(stop=AsyncMock())
    session._playwright = playwright
    context.close.side_effect = RuntimeError("closed")
    with pytest.raises(RuntimeError):
        await session.close()
    assert session._context is None
    playwright.stop.assert_awaited_once()


async def test_transport_failure_after_renewal():
    with respx.mock(base_url=BASE) as mock:
        mock.get("/projects").mock(
            side_effect=[httpx.Response(401), httpx.ConnectError("failed")]
        )
        async with PolarionClient(config(), min_interval=0) as client:
            client._sso.headers = AsyncMock(return_value={"X-Polarion-REST-Token": "t"})
            with pytest.raises(PolarionError, match="after SSO renewal"):
                await client.get("/projects")
