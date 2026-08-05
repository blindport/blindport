"""Browser regressions for account access, payments, and narrow layouts."""

from __future__ import annotations

import os
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest
from playwright.sync_api import Browser, Page, Playwright, sync_playwright


ONION_HOST = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaam2dqd.onion"


@dataclass(frozen=True)
class BrowserServer:
    base_url: str
    artifacts: Path
    database: Path


def _unused_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture(scope="session")
def browser_server(tmp_path_factory: pytest.TempPathFactory) -> Iterator[BrowserServer]:
    state_dir = tmp_path_factory.mktemp("browser-state")
    artifacts = Path(os.environ.get("BROWSER_ARTIFACT_DIR", "tmp/browser-artifacts"))
    artifacts.mkdir(parents=True, exist_ok=True)
    log_path = artifacts / "server.log"
    port = _unused_port()
    base_url = f"http://127.0.0.1:{port}"
    env = os.environ.copy()
    source_path = str(Path(__file__).resolve().parents[2] / "backend" / "src")
    env["PYTHONPATH"] = os.pathsep.join(
        path for path in (source_path, env.get("PYTHONPATH", "")) if path
    )
    env.update(
        {
            "ENVIRONMENT": "test",
            "DATABASE_URL": f"sqlite:///{state_dir / 'browser.db'}",
            "DATABASE_MIGRATE_ON_STARTUP": "true",
            "CA_DIR": str(state_dir / "ca"),
            "SECRET_KEY": "browser-ci-secret",
            "ADMIN_TOKEN": "BROWSERCIADMIN0000",
            "PAYMENT_ENABLED_METHODS": "lightning,nwc,stablecoin_swap",
            "STABLECOIN_PAYMENTS_ENABLED": "true",
            "STABLECOIN_SWAP_MARKUP_BPS": "1000",
            "BOLTZ_WEB_URL": "https://boltz.example",
            "PAYMENT_LIGHTNING_ADAPTER": "mock",
            "PAYMENT_NWC_ADAPTER": "mock",
            "CREDENTIAL_ENCRYPTION_KEY": "cd" * 32,
            "PAYMENT_RECONCILIATION_ENABLED": "true",
            "BILLING_YEARLY_ENABLED": "true",
            "RELAY_SHARED_IPS": "203.0.113.20",
            "RELAY_SHARED_TCP_PORTS": "10000-10015",
            "RELAY_SHARED_UDP_PORTS": "10000-10015",
            "RELAY_POOL_DOMAINS": "relay1.test,relay2.test",
            "RELAY_MANAGED_SUFFIXES": "relay.test",
            "ONION_HOST": ONION_HOST,
        }
    )
    with log_path.open("w", encoding="utf-8") as log_file:
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "blindport.main:app",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
            ],
            env=env,
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )
        try:
            for _ in range(100):
                if process.poll() is not None:
                    pytest.fail(f"browser test server exited early; inspect {log_path}")
                try:
                    with urllib.request.urlopen(
                        f"{base_url}/api/v1/health/ready", timeout=1
                    ) as response:
                        if response.status == 200:
                            break
                except (urllib.error.URLError, TimeoutError):
                    time.sleep(0.1)
            else:
                pytest.fail(
                    f"browser test server did not become ready; inspect {log_path}"
                )
            yield BrowserServer(
                base_url=base_url,
                artifacts=artifacts,
                database=state_dir / "browser.db",
            )
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


@pytest.fixture(scope="session")
def playwright_runtime() -> Iterator[Playwright]:
    with sync_playwright() as runtime:
        yield runtime


@pytest.fixture(scope="session")
def browser(playwright_runtime: Playwright) -> Iterator[Browser]:
    instance = playwright_runtime.chromium.launch(headless=True)
    yield instance
    instance.close()


@contextmanager
def _capture_failure(page: Page, path: Path) -> Iterator[None]:
    try:
        yield
    except Exception:
        masks = [
            page.locator(selector)
            for selector in ("#accountToken", "#payBolt11", "#qrBox")
        ]
        try:
            page.screenshot(path=path, full_page=True, mask=masks)
        except Exception:
            # Preserve the test failure when the page closed before capture completed.
            pass
        raise


def _assert_layout(page: Page) -> None:
    dimensions = page.evaluate(
        """() => ({
          viewport: window.innerWidth,
          document: document.documentElement.scrollWidth,
          body: document.body.scrollWidth,
        })"""
    )
    assert dimensions["document"] <= dimensions["viewport"], dimensions
    assert dimensions["body"] <= dimensions["viewport"], dimensions
    overflowing = page.locator("button, a.button-link, .segmented span").evaluate_all(
        """elements => elements.filter(element => {
          const style = getComputedStyle(element);
          return style.display !== 'none' &&
            (element.scrollWidth > element.clientWidth + 1 ||
             element.scrollHeight > element.clientHeight + 1);
        }).map(element => element.textContent.trim())"""
    )
    assert overflowing == []


def _signup(playwright_runtime: Playwright, base_url: str) -> dict[str, str]:
    request = playwright_runtime.request.new_context(base_url=base_url)
    try:
        response = request.post("/api/v2/signup")
        assert response.ok, response.text()
        return response.json()
    finally:
        request.dispose()


@pytest.mark.parametrize("width", [320, 360, 390, 1440])
def test_landing_explanation_has_no_horizontal_overflow(
    browser: Browser,
    browser_server: BrowserServer,
    width: int,
) -> None:
    context = browser.new_context(viewport={"width": width, "height": 900})
    page = context.new_page()
    errors: list[str] = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    try:
        with _capture_failure(
            page, browser_server.artifacts / f"landing-{width}-failure.png"
        ):
            page.goto(browser_server.base_url, wait_until="networkidle")
            assert page.get_by_role(
                "heading", name="Different tools optimize for different jobs"
            ).is_visible()
            assert (
                page.get_by_role("heading", name="Blindport", exact=True).count() == 1
            )
            brand_mark = page.locator(".brand-mark")
            assert brand_mark.is_visible()
            assert brand_mark.evaluate(
                "image => image.complete && image.naturalWidth === 512"
            )
            assert ONION_HOST not in page.locator(".site-footer").inner_text()
            assert page.get_by_role("link", name="Onion", exact=True).count() == 0
            page.get_by_role("link", name="Choose Relay").click()
            assert page.locator(
                'input[name="orderProduct"][value="relay"]'
            ).is_checked()
            _assert_layout(page)
            assert errors == []
    finally:
        context.close()


@pytest.mark.parametrize("width", [320, 1440])
def test_service_terms_are_readable_without_horizontal_overflow(
    browser: Browser,
    browser_server: BrowserServer,
    width: int,
) -> None:
    context = browser.new_context(viewport={"width": width, "height": 900})
    page = context.new_page()
    errors: list[str] = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    try:
        with _capture_failure(
            page, browser_server.artifacts / f"terms-{width}-failure.png"
        ):
            page.goto(f"{browser_server.base_url}/terms", wait_until="networkidle")
            assert page.get_by_role("heading", name="Service terms").is_visible()
            assert page.get_by_role("heading", name="Traffic and fair use").is_visible()
            assert page.get_by_role(
                "heading", name="Privacy and threat model"
            ).is_visible()
            assert page.locator("main > article > section").count() == 7
            footer = page.locator(".site-footer")
            footer_link = footer.get_by_role("link", name="Terms", exact=True)
            assert footer_link.get_attribute("href") == "/terms"
            assert footer_link.bounding_box()["height"] >= 44
            support_link = footer.get_by_role("link", name="Support", exact=True)
            assert support_link.get_attribute("href") == "mailto:support@blindport.com"
            assert support_link.bounding_box()["height"] >= 44
            nostr_link = footer.get_by_role("link", name="Nostr", exact=True)
            assert nostr_link.get_attribute("href") == (
                "https://njump.me/"
                "npub1xqthzgt6zv39l3tanlmlxa6aay48n0j3lukxzgs0ygwg5g5j8elquxchn8"
            )
            assert nostr_link.get_attribute("rel") == "me"
            assert nostr_link.get_attribute("target") is None
            assert nostr_link.bounding_box()["height"] >= 44
            _assert_layout(page)
            assert errors == []
    finally:
        context.close()


def test_saved_accounts_migrate_switch_and_forget(
    browser: Browser,
    browser_server: BrowserServer,
    playwright_runtime: Playwright,
) -> None:
    first = _signup(playwright_runtime, browser_server.base_url)
    second = _signup(playwright_runtime, browser_server.base_url)
    context = browser.new_context(viewport={"width": 390, "height": 844})
    page = context.new_page()
    errors: list[str] = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    try:
        with _capture_failure(page, browser_server.artifacts / "accounts-failure.png"):
            page.goto(f"{browser_server.base_url}/dashboard")
            page.evaluate(
                "token => localStorage.setItem('blindport_token', token)",
                first["token"],
            )
            page.reload(wait_until="networkidle")
            assert page.locator("#savedAccountForm").is_visible()
            page.locator("#savedAccountForm").get_by_role(
                "button", name="Sign in"
            ).click()
            page.locator("#dashboardRoot").wait_for(state="visible")
            page.get_by_text("Account token", exact=True).click()
            page.locator("#accountToken").wait_for(state="visible")
            assert (
                page.locator("#dashboardRoot").get_attribute("data-account-id")
                == first["account_id"]
            )

            page.locator("#logoutBtn").click()
            page.locator("#loginForm").wait_for(state="visible")
            page.locator("#tokenInput").fill(second["token"])
            page.locator("#loginForm").get_by_role("button", name="Sign in").click()
            page.locator("#dashboardRoot").wait_for(state="visible")
            page.get_by_text("Account token", exact=True).click()
            page.locator("#accountToken").wait_for(state="visible")
            assert (
                page.locator("#dashboardRoot").get_attribute("data-account-id")
                == second["account_id"]
            )

            page.locator("#logoutBtn").click()
            page.locator("#savedAccountForm").wait_for(state="visible")
            options = page.locator("#savedAccountSelect option")
            assert options.count() == 2
            page.locator("#savedAccountSelect").select_option(
                label=f"Account {first['account_id']}"
            )
            page.locator("#savedAccountForm").get_by_role(
                "button", name="Sign in"
            ).click()
            page.locator("#dashboardRoot").wait_for(state="visible")
            page.get_by_text("Account token", exact=True).click()
            page.locator("#accountToken").wait_for(state="visible")
            assert (
                page.locator("#dashboardRoot").get_attribute("data-account-id")
                == first["account_id"]
            )

            page.once("dialog", lambda dialog: dialog.accept())
            page.locator("#forgetAccountBtn").click()
            page.locator("#savedAccountForm").wait_for(state="visible")
            assert page.locator("#savedAccountSelect option").count() == 1
            assert (
                second["account_id"] in page.locator("#savedAccountSelect").inner_text()
            )
            _assert_layout(page)
            assert errors == []
    finally:
        context.close()


def test_regular_admin_login_never_enters_customer_browser_storage(
    browser: Browser,
    browser_server: BrowserServer,
    playwright_runtime: Playwright,
) -> None:
    account = _signup(playwright_runtime, browser_server.base_url)
    context = browser.new_context(viewport={"width": 390, "height": 844})
    page = context.new_page()
    try:
        page.goto(f"{browser_server.base_url}/dashboard", wait_until="networkidle")
        page.evaluate(
            """token => localStorage.setItem("blindport_accounts_v1", JSON.stringify([{
              token,
              accountId: "",
              lastUsedAt: Date.now(),
            }]))""",
            "BROWSERCIADMIN0000",
        )
        page.reload(wait_until="networkidle")
        page.locator("#savedAccountForm").get_by_role("button", name="Sign in").click()
        page.get_by_role("heading", name="Admin", exact=True).wait_for(state="visible")

        storage = page.evaluate(
            """() => ({
              accounts: localStorage.getItem("blindport_accounts_v1"),
              legacy: localStorage.getItem("blindport_token"),
            })"""
        )
        assert storage == {"accounts": None, "legacy": None}
        cookies = {cookie["name"]: cookie["value"] for cookie in context.cookies()}
        assert "blindport_token" not in cookies
        assert "blindport_admin_session" in cookies
        assert "BROWSERCIADMIN0000" not in cookies["blindport_admin_session"]

        account_row = page.locator("tr", has_text=account["account_id"])
        account_row.get_by_role("button", name="Suspend").click()
        page.wait_for_url("**/admin#accounts-title")
        assert (
            "Suspended"
            in page.locator("tr", has_text=account["account_id"]).inner_text()
        )
        request = playwright_runtime.request.new_context(
            base_url=browser_server.base_url
        )
        try:
            suspended = request.get(
                "/api/v2/me",
                headers={"Authorization": f"Bearer {account['token']}"},
            )
            assert suspended.status == 403
        finally:
            request.dispose()
        _assert_layout(page)
    finally:
        context.close()


def test_dashboard_payment_qr_and_copy_controls(
    browser: Browser,
    browser_server: BrowserServer,
    playwright_runtime: Playwright,
) -> None:
    account = _signup(playwright_runtime, browser_server.base_url)
    request = playwright_runtime.request.new_context(base_url=browser_server.base_url)
    try:
        response = request.post(
            "/api/v1/subscriptions",
            headers={"Authorization": f"Bearer {account['token']}"},
            data={"product": "port", "transport": "tcp"},
        )
        assert response.ok, response.text()
        subscription = response.json()
    finally:
        request.dispose()

    context = browser.new_context(viewport={"width": 320, "height": 800})
    context.grant_permissions(
        ["clipboard-read", "clipboard-write"], origin=browser_server.base_url
    )
    context.add_cookies(
        [
            {
                "name": "blindport_token",
                "value": account["token"],
                "url": browser_server.base_url,
                "sameSite": "Lax",
            }
        ]
    )
    page = context.new_page()
    errors: list[str] = []
    page.on("pageerror", lambda error: errors.append(error.stack or str(error)))
    try:
        with _capture_failure(page, browser_server.artifacts / "payment-failure.png"):
            page.goto(f"{browser_server.base_url}/dashboard", wait_until="networkidle")
            page.get_by_text("Account token", exact=True).click()
            page.locator("#revealTokenBtn").click()
            assert page.locator("#accountToken").input_value() == account["token"]
            page.locator("#copyAccountTokenBtn").click()
            assert page.evaluate("navigator.clipboard.readText()") == account["token"]

            assert page.get_by_role("heading", name="Awaiting payment").is_visible()
            assert page.locator("#framedRunCommand").count() == 0
            assert page.locator("#wireGuardRunCommand").count() == 0

            with page.expect_response(
                lambda payment: (
                    payment.url.endswith("/api/v1/payments")
                    and payment.request.method == "POST"
                )
            ) as payment_response_info:
                page.locator(f'.payBtn[data-sub-id="{subscription["id"]}"]').click()
            payment_response = payment_response_info.value
            assert payment_response.ok, payment_response.text()
            payment = payment_response.json()
            page.locator("#qrBox svg").wait_for(state="visible")
            invoice = page.locator("#payBolt11").text_content()
            assert invoice == payment["invoice"]
            assert (
                page.locator("#payUri").get_attribute("href") == f"lightning:{invoice}"
            )
            qr_opening = page.locator("#qrBox svg").evaluate(
                "element => element.outerHTML.split('>', 1)[0]"
            )
            assert "viewBox=" in qr_opening
            assert " width=" not in qr_opening
            assert " height=" not in qr_opening
            qr_width = page.locator("#qrBox").bounding_box()["width"]
            assert 220 <= qr_width <= 340

            page.locator("#copyInvoiceBtn").click()
            assert page.evaluate("navigator.clipboard.readText()") == invoice
            assert page.locator("#copyInvoiceBtn").text_content() == "Copied"

            page.reload(wait_until="networkidle")
            page.locator("#qrBox svg").wait_for(state="visible")
            assert page.locator("#payStatus").text_content() == (
                "Payment still pending. Continue with this invoice."
            )
            assert page.locator("#payBolt11").text_content() == invoice
            assert page.locator("#qrBox svg").is_visible()
            _assert_layout(page)
            assert errors == []
    finally:
        context.close()


def test_dashboard_stablecoin_checkout_opens_external_boltz_flow(
    browser: Browser,
    browser_server: BrowserServer,
    playwright_runtime: Playwright,
) -> None:
    account = _signup(playwright_runtime, browser_server.base_url)
    request = playwright_runtime.request.new_context(base_url=browser_server.base_url)
    try:
        response = request.post(
            "/api/v1/subscriptions",
            headers={"Authorization": f"Bearer {account['token']}"},
            data={"product": "ip"},
        )
        assert response.ok, response.text()
        subscription = response.json()
    finally:
        request.dispose()

    context = browser.new_context(viewport={"width": 320, "height": 800})
    context.add_cookies(
        [
            {
                "name": "blindport_token",
                "value": account["token"],
                "url": browser_server.base_url,
                "sameSite": "Lax",
            }
        ]
    )
    context.route(
        "https://boltz.example/**",
        lambda route: route.fulfill(
            status=200, content_type="text/html", body="Boltz test"
        ),
    )
    page = context.new_page()
    errors: list[str] = []
    page.on("pageerror", lambda error: errors.append(error.stack or str(error)))
    try:
        page.goto(f"{browser_server.base_url}/dashboard", wait_until="networkidle")
        with (
            page.expect_popup() as popup_info,
            page.expect_response(
                lambda payment: (
                    payment.url.endswith("/api/v1/payments")
                    and payment.request.method == "POST"
                )
            ) as payment_response_info,
        ):
            page.locator(
                f'.stablecoinPayBtn[data-sub-id="{subscription["id"]}"]'
            ).click()

        payment_response = payment_response_info.value
        assert payment_response.ok, payment_response.text()
        payment = payment_response.json()
        popup = popup_info.value
        popup.wait_for_url("https://boltz.example/**")
        checkout = urlsplit(popup.url)
        assert parse_qs(checkout.query) == {
            "sendAsset": ["USDC-BASE"],
            "receiveAsset": ["LN"],
            "destination": [payment["invoice"]],
        }
        assert payment["base_amount_sats"] == 7500
        assert payment["markup_sats"] == 750
        assert payment["amount_sats"] == 8250
        assert page.locator("#payAmount").text_content() == "8250"
        assert (
            "7500 sats service price + 750 sats"
            in page.locator("#payBreakdown").text_content()
        )
        assert page.locator("#payUri").get_attribute("target") == "_blank"
        assert page.locator("#payUri").get_attribute("rel") == (
            "noopener noreferrer external"
        )
        assert page.locator("#stablecoinNotice").is_visible()
        assert page.locator("#qrBox").is_hidden()
        _assert_layout(page)
        assert errors == []
        popup.close()
    finally:
        context.close()


def test_active_relay_setup_command_is_complete_and_mode_specific(
    browser: Browser,
    browser_server: BrowserServer,
    playwright_runtime: Playwright,
) -> None:
    account = _signup(playwright_runtime, browser_server.base_url)
    request = playwright_runtime.request.new_context(base_url=browser_server.base_url)
    try:
        response = request.post(
            "/api/v1/subscriptions",
            headers={"Authorization": f"Bearer {account['token']}"},
            data={"product": "relay", "domain": "browser-setup.relay.test"},
        )
        assert response.ok, response.text()
        subscription = response.json()
    finally:
        request.dispose()

    now = datetime.now(UTC)
    with sqlite3.connect(browser_server.database) as database:
        database.execute(
            "UPDATE subscription SET status = ?, current_period_start = ?, "
            "current_period_end = ? WHERE public_id = ?",
            (
                "ACTIVE",
                now.isoformat(),
                (now + timedelta(days=30)).isoformat(),
                subscription["id"].replace("-", ""),
            ),
        )

    context = browser.new_context(viewport={"width": 320, "height": 800})
    context.grant_permissions(
        ["clipboard-read", "clipboard-write"], origin=browser_server.base_url
    )
    context.add_cookies(
        [
            {
                "name": "blindport_token",
                "value": account["token"],
                "url": browser_server.base_url,
                "sameSite": "Lax",
            }
        ]
    )
    page = context.new_page()
    try:
        with _capture_failure(
            page, browser_server.artifacts / "relay-setup-failure.png"
        ):
            page.goto(f"{browser_server.base_url}/dashboard", wait_until="networkidle")
            assert page.get_by_role("heading", name="Connect your service").is_visible()
            assert page.locator("#wireGuardRunCommand").count() == 0
            card = page.locator(f'[data-sub-id="{subscription["id"]}"]')
            card.get_by_text("Endpoint details", exact=True).click()
            assert card.get_by_text("Subscription ID").is_visible()
            assert card.get_by_text(subscription["id"], exact=True).is_visible()
            quick_command = page.locator("#framedRunCommand").text_content()
            assert (
                "/downloads/install.sh | BLINDPORT_DOWNLOAD_BASE_URL=" in quick_command
            )
            assert "BLINDPORT_INSTALL_DIR=" in quick_command
            assert '"$HOME/.local/bin/blindportd"' in quick_command
            assert "-upstream=127.0.0.1:443" in quick_command
            page.get_by_role("button", name="Copy command", exact=True).click()
            assert page.evaluate("navigator.clipboard.readText()") == quick_command
            disclosure = page.locator(".advanced-config").filter(
                has_text="Generated multi-endpoint config"
            )
            summary = disclosure.locator("summary")
            assert summary.get_attribute("class") == "disclosure-summary"
            assert (
                summary.evaluate("element => getComputedStyle(element).cursor")
                == "pointer"
            )
            assert disclosure.locator(".disclosure-icon").evaluate(
                "element => ({width: getComputedStyle(element).width, "
                "height: getComputedStyle(element).height})"
            ) == {"width": "10px", "height": "10px"}
            summary.click()
            command = page.locator("#framedConfigInstallCommand").text_content()
            assert subscription["id"] in command
            assert '"upstream": "127.0.0.1:443"' in command
            assert 'cat > "$HOME/.config/blindport/config.json"' in command
            page.get_by_role("button", name="Copy install command").click()
            assert page.evaluate("navigator.clipboard.readText()") == command
            page.get_by_role("button", name="Copy JSON config").click()
            assert subscription["id"] in page.evaluate("navigator.clipboard.readText()")
            symbol = page.locator(".drawer-symbol")
            center_offsets = symbol.evaluate(
                """element => {
                  const before = getComputedStyle(element, "::before");
                  const after = getComputedStyle(element, "::after");
                  return {beforeTop: before.top, afterTop: after.top,
                          beforeLeft: before.left, afterLeft: after.left};
                }"""
            )
            assert center_offsets == {
                "beforeTop": "15px",
                "afterTop": "15px",
                "beforeLeft": "8px",
                "afterLeft": "8px",
            }
            _assert_layout(page)
    finally:
        context.close()


def test_inline_nwc_connects_pays_recovers_and_never_renders_secret(
    browser: Browser,
    browser_server: BrowserServer,
    playwright_runtime: Playwright,
) -> None:
    account = _signup(playwright_runtime, browser_server.base_url)
    request = playwright_runtime.request.new_context(base_url=browser_server.base_url)
    try:
        response = request.post(
            "/api/v1/subscriptions",
            headers={"Authorization": f"Bearer {account['token']}"},
            data={"product": "port", "transport": "tcp"},
        )
        assert response.ok, response.text()
        subscription = response.json()
    finally:
        request.dispose()

    context = browser.new_context(viewport={"width": 320, "height": 800})
    context.add_cookies(
        [
            {
                "name": "blindport_token",
                "value": account["token"],
                "url": browser_server.base_url,
                "sameSite": "Lax",
            }
        ]
    )
    page = context.new_page()
    errors: list[str] = []
    page.on("pageerror", lambda error: errors.append(error.stack or str(error)))
    secret = "nostr+walletconnect://browser-inline-secret"
    try:
        page.goto(f"{browser_server.base_url}/dashboard", wait_until="networkidle")
        card = page.locator(f'.subscription-card[data-sub-id="{subscription["id"]}"]')
        form = card.locator(".inline-nwc-form")
        assert form.is_visible()
        assert "Automatic renewal stays off." in form.inner_text()
        form.locator(".inlineNwcUri").fill(secret)
        with (
            page.expect_response(
                lambda response: (
                    response.url.endswith("/api/v1/me/nwc")
                    and response.request.method == "POST"
                )
            ) as nwc_response_info,
            page.expect_response(
                lambda response: (
                    response.url.endswith("/api/v1/payments")
                    and response.request.method == "POST"
                )
            ) as payment_response_info,
        ):
            form.get_by_role("button", name="Connect and pay").click()
        assert nwc_response_info.value.ok
        assert payment_response_info.value.ok
        payment = payment_response_info.value.json()
        assert payment["method"] == "nwc"
        assert form.locator(".inlineNwcUri").input_value() == ""
        assert secret not in page.locator("body").inner_html()
        assert page.locator(".autoRenewToggle").count() == 0

        page.reload(wait_until="networkidle")
        card = page.locator(f'.subscription-card[data-sub-id="{subscription["id"]}"]')
        assert card.locator(".cardStatus").text_content() == (
            "Connected wallet payment is still pending."
        )
        assert secret not in page.locator("body").inner_html()
        assert page.locator(".autoRenewToggle").count() == 0
        _assert_layout(page)
        assert errors == []
    finally:
        context.close()


def test_inline_nwc_handles_existing_manual_payment_conflict(
    browser: Browser,
    browser_server: BrowserServer,
    playwright_runtime: Playwright,
) -> None:
    account = _signup(playwright_runtime, browser_server.base_url)
    request = playwright_runtime.request.new_context(base_url=browser_server.base_url)
    headers = {"Authorization": f"Bearer {account['token']}"}
    try:
        subscription_response = request.post(
            "/api/v1/subscriptions",
            headers=headers,
            data={"product": "ip"},
        )
        assert subscription_response.ok
        subscription = subscription_response.json()
        payment_response = request.post(
            "/api/v1/payments",
            headers=headers,
            data={"subscription_id": subscription["id"], "method": "lightning"},
        )
        assert payment_response.ok
        existing = payment_response.json()
    finally:
        request.dispose()

    context = browser.new_context(viewport={"width": 390, "height": 844})
    context.add_cookies(
        [
            {
                "name": "blindport_token",
                "value": account["token"],
                "url": browser_server.base_url,
                "sameSite": "Lax",
            }
        ]
    )
    page = context.new_page()
    try:
        page.goto(f"{browser_server.base_url}/dashboard", wait_until="networkidle")
        card = page.locator(f'.subscription-card[data-sub-id="{subscription["id"]}"]')
        form = card.locator(".inline-nwc-form")
        form.locator(".inlineNwcUri").fill("nostr+walletconnect://conflict-secret")
        with page.expect_response(
            lambda response: (
                response.url.endswith("/api/v1/payments")
                and response.request.method == "POST"
            )
        ) as conflict_info:
            form.get_by_role("button", name="Connect and pay").click()
        conflict = conflict_info.value
        assert conflict.status == 409
        assert conflict.json()["existing_payment"]["id"] == existing["id"]
        assert page.locator("#payBolt11").text_content() == existing["invoice"]
        assert page.locator("#payPanel").is_visible()
        assert "conflict-secret" not in page.locator("body").inner_html()
        _assert_layout(page)
    finally:
        context.close()
