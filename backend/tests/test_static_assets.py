"""Frontend structure and browser asset assertions without a browser dependency."""

from __future__ import annotations

import re
from html.parser import HTMLParser
from pathlib import Path

import blindport


class DocumentInspector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.ids: list[str] = []
        self.scripts_without_src = 0
        self.style_elements = 0
        self.inline_attributes: list[str] = []
        self.tables = 0
        self.captions = 0
        self.unscoped_headers = 0
        self.table_cells_without_labels = 0
        self._table_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if element_id := attributes.get("id"):
            self.ids.append(element_id)
        if tag == "script" and not attributes.get("src"):
            self.scripts_without_src += 1
        if tag == "style":
            self.style_elements += 1
        self.inline_attributes.extend(
            name for name, _ in attrs if name == "style" or name.startswith("on")
        )
        if tag == "table":
            self.tables += 1
            self._table_depth += 1
        elif tag == "caption" and self._table_depth:
            self.captions += 1
        elif tag == "th" and self._table_depth and attributes.get("scope") not in {"col", "row"}:
            self.unscoped_headers += 1
        elif tag == "td" and self._table_depth and not attributes.get("data-label"):
            self.table_cells_without_labels += 1

    def handle_endtag(self, tag: str) -> None:
        if tag == "table":
            self._table_depth -= 1


def _asset(name: str) -> str:
    package = Path(blindport.__file__).parent
    return (package / name).read_text(encoding="utf-8")


def _inspect(document: str) -> DocumentInspector:
    inspector = DocumentInspector()
    inspector.feed(document)
    return inspector


def test_order_assets_use_anonymous_order_only_without_a_browser_token() -> None:
    account_storage = _asset("static/account-storage.js")
    landing = _asset("static/landing.js")
    dashboard = _asset("static/dashboard.js")
    login = _asset("static/login.js")

    assert 'existingToken ? "/api/v1/subscriptions" : "/api/v2/orders"' in landing
    assert "if (existingToken)" in landing
    assert "storeToken(result.token, result.account_id)" in landing
    assert 'document.getElementById("tokenSavedCheck")' in landing
    assert 'window.location.assign("/dashboard")' in landing
    assert "heading.focus({ preventScroll: true })" in landing
    assert 'heading.scrollIntoView({ block: "start", behavior: "instant" })' in landing
    assert "accounts.activeToken()" in landing
    assert "body: JSON.stringify(orderBody())" in landing
    assert 'document.querySelectorAll(".product-jump")' in landing
    assert "link.dataset.orderProduct" in landing

    assert 'const STORAGE_KEY = "blindport_accounts_v1"' in account_storage
    assert 'const LEGACY_KEY = "blindport_token"' in account_storage
    assert "migrateLegacyToken()" in account_storage
    assert "MAX_ACCOUNTS = 20" in account_storage
    assert "if (accounts.length === 0)" in account_storage
    assert "localStorage.removeItem(STORAGE_KEY)" in account_storage
    assert (
        "if (!legacyToken || save(legacyToken)) localStorage.removeItem(LEGACY_KEY)"
        in account_storage
    )
    assert "if (removed && readCookie() === normalizedToken) clearCookie()" in account_storage
    assert 'document.getElementById("savedAccountToken").value = account.token' in login
    assert "accounts.forget(account.token)" in login
    assert "!accounts.forget(account.token)" in login
    assert 'action="/login"' in _asset("templates/login.html")
    assert 'name="token"' in _asset("templates/login.html")
    assert 'document.getElementById("loginForm").addEventListener' in login
    assert "if (token) accounts.forget(token)" in login

    assert "billing_term: term" in dashboard
    assert "payment.period_days" in dashboard
    assert 'name="orderBillingTerm"' in _asset("templates/landing.html")
    assert 'name="newBillingTerm"' in _asset("templates/dashboard.html")
    assert 'name="paymentTerm-{{ s.public_id }}"' in _asset("templates/dashboard.html")
    assert 'current.status === "paid"' in dashboard
    assert 'current.status === "expired"' in dashboard
    assert 'current.status === "failed"' in dashboard
    assert "verify-domain" in dashboard
    assert "Check DNS" in _asset("templates/dashboard.html")
    assert "CNAME verification required" in _asset("templates/dashboard.html")
    assert "domain_verification_token" in _asset("templates/dashboard.html")
    assert "accounts.save(token, accountId)" in dashboard
    assert "accounts.clearActive()" in dashboard
    assert "accounts.forget(token)" in dashboard
    assert "if (!accounts.forget(token))" in dashboard
    assert 'window.location.assign("/dashboard")' in dashboard
    assert "accounts.copyText(token)" in dashboard
    assert "const button = event.currentTarget;" in dashboard
    assert 'button.textContent = copied ? "Copied"' in dashboard
    assert "JSON.stringify(body)" in dashboard
    assert "`${body.domain} (CNAME)`" in landing


def test_templates_have_accessible_external_only_structure() -> None:
    templates = [
        _asset("templates/base.html"),
        _asset("templates/landing.html"),
        _asset("templates/dashboard.html"),
        _asset("templates/guide.html"),
        _asset("templates/admin.html"),
        _asset("templates/login.html"),
        _asset("templates/admin_login.html"),
        _asset("templates/terms.html"),
    ]
    for template in templates:
        inspected = _inspect(template)
        assert inspected.scripts_without_src == 0
        assert inspected.style_elements == 0
        assert inspected.inline_attributes == []

    base = templates[0]
    assert 'class="skip-link" href="#main-content"' in base
    assert 'aria-label="Primary navigation"' in base
    assert '<a href="/admin">' not in base
    assert '<a href="/guide">Guide</a>' in base
    assert '<a href="/terms">Terms</a>' in base
    assert '<a href="mailto:support@blindport.com">Support</a>' in base
    assert '<a href="/release-key.asc">Release key</a>' in base
    assert (
        '<a href="https://njump.me/'
        'npub1xqthzgt6zv39l3tanlmlxa6aay48n0j3lukxzgs0ygwg5g5j8elquxchn8" '
        'rel="me">Nostr</a>'
    ) in base
    assert 'target="_blank"' not in base
    assert 'id="main-content" tabindex="-1"' in base

    landing = templates[1]
    for element_id in (
        "planPanel",
        "configPanel",
        "reviewPanel",
        "orderStatus",
        "tokenBackup",
        "tokenSavedCheck",
    ):
        assert f'id="{element_id}"' in landing
    assert 'role="status" aria-live="polite"' in landing
    assert '<script src="/static/account-storage.js"></script>' in landing
    assert '<script src="/static/landing.js"></script>' in landing
    assert 'agree to the <a href="/terms">service terms</a>' in landing

    dashboard = templates[2]
    assert "User #" not in dashboard
    assert "{{ user.id }}" not in dashboard
    assert "{{ user.public_id }}" in dashboard
    assert "{{ s.id }}" not in dashboard
    assert 'data-sub-id="{{ s.public_id }}"' in dashboard
    assert "{{ client_config_json }}" in dashboard
    assert 'role="status" aria-live="polite"' in dashboard
    assert 'data-monthly-price="{{ s.monthly_price_sats }}"' in dashboard
    assert 'data-yearly-price="{{ s.yearly_price_sats }}"' in dashboard
    assert "one exact CNAME record" in dashboard
    assert 'id="accountToken" type="password" readonly' in dashboard
    assert 'id="copyInvoiceBtn"' in dashboard
    assert 'id="qrBox" role="img" aria-label="Lightning invoice QR code"' in dashboard
    assert 'id="framedSetupCommand"' in dashboard
    assert 'id="framedConfigInstallCommand"' in dashboard
    assert 'id="generatedClientConfig"' in dashboard
    assert "Choose Relay for a domain" in dashboard
    assert "Routed WireGuard /32" in dashboard
    assert '<script src="/static/account-storage.js"></script>' in dashboard
    assert 'agree to the <a href="/terms">service terms</a>' in dashboard

    login = templates[5]
    assert 'id="savedAccountForm"' in login
    assert 'id="savedAccountSelect"' in login
    assert '<script src="/static/account-storage.js"></script>' in login

    guide = templates[3]
    assert '<a href="mailto:support@blindport.com">support@blindport.com</a>' in guide
    assert '<a href="mailto:security@blindport.com">security@blindport.com</a>' in guide
    assert "18ED E472 6C14 1484 4923 D6FF 14EA BFF7 39C1 6205" in guide

    assert landing.count('class="network-path" role="img" aria-label=') == 4

    admin = _inspect(templates[4])
    assert admin.tables == 4
    assert admin.captions == admin.tables
    assert admin.unscoped_headers == 0
    assert admin.table_cells_without_labels == 0
    assert "u.public_id" in templates[4]
    assert "account_by_user_id" in templates[4]
    assert "{{ s.id }}" not in templates[4]
    assert "{{ s.public_id }}" in templates[4]
    assert "{{ p.subscription_id }}" not in templates[4]
    assert "{{ reminder.subscription_id }}" not in templates[4]


def test_content_covers_product_boundaries_and_client_operations() -> None:
    landing = _asset("templates/landing.html")
    guide = _asset("templates/guide.html")

    for term in (
        "changing IPs",
        "CGNAT",
        "inbound router setup",
        "residential IP",
        "application and data move to provider hardware",
        "Cloudflare Tunnel",
        "Cloudflare manages the web edge",
        "Four ways to put a home service online",
        "VPS alone",
        "Blindport ingress",
        "App, data, TLS stay here",
        "not an anonymity network",
        "Tor SOCKS5",
        "One dedicated public IPv4",
        "One shared-IP tuple",
        "Managed subdomain",
        "Bring your own subdomain",
        "exact DNS-only CNAME record",
        "fixed service term",
        "amd64",
    ):
        assert term in landing
    assert not re.search(r"\d+ available", landing)

    for term in (
        "sha256sum -c",
        "Token and state",
        "Static mappings",
        "Docker socket warning",
        "TLS and HTTP-01",
        "Routed WireGuard mode",
        "Tor SOCKS5 transport",
        "does not fall back to a direct connection",
        "rejects combining",
        "Troubleshooting",
        "Current limitations",
        "CAP_NET_ADMIN",
        "native UDP or ICMP semantics",
        "other IPv4 protocols",
        "ghcr.io/blindport/blindportd",
        "https://github.com/blindport/blindport/issues",
        "-kind=relay",
        "-upstream=127.0.0.1:8080",
        "only after creating the static mapping file",
        "GitHub Actions builds versioned static Linux binaries",
        "only detects transfer corruption",
        "does not authenticate the CI-built binary",
        "build the checked-out source locally",
        "GPG signature authenticates the source history, not GitHub-built artifacts",
        "docker build -f docker/go.Dockerfile --target blindportd -t blindportd:local .",
    ):
        assert term in guide
    run_section = guide.split('<section id="run">', 1)[1].split("</section>", 1)[0]
    assert '-config="$HOME/.config/blindport/config.json"</code>' not in run_section
    assert "canonical, unique UUIDv4 values" in guide

    base = _asset("templates/base.html")
    assert "https://github.com/blindport/blindport" in base
    assert "https://github.com/blindport/blindport/issues" in base
    assert "volumes:\n  blindport-state:" in guide


def test_css_defines_mobile_layout_targets_and_responsive_tables() -> None:
    css = _asset("static/style.css")

    assert "min-height: 44px" in css
    assert "@media (max-width: 720px)" in css
    assert "@media (max-width: 480px)" in css
    assert ".responsive-table td::before" in css
    assert "content: attr(data-label)" in css
    assert ".skip-link:focus" in css
    assert ":focus-visible" in css
    assert "scroll-padding-top: 80px" in css
    assert "scroll-margin-top: 80px" in css
    assert ".network-path" in css
    assert "clip-path: polygon(0 0, 100% 50%, 0 100%)" in css
    assert 'content: ""' in css
    assert ".account-access" in css
    assert "overflow-x: clip" in css
    assert "a { color: var(--accent-dark); overflow-wrap: anywhere; }" in css
    assert "linear-gradient" not in css
    assert "radial-gradient" not in css
    assert "--radius: 6px" in css


def test_rendered_pages_are_semantic_responsive_and_not_cacheable(app_client) -> None:
    client, _ = app_client

    landing = client.get("/")
    guide = client.get("/guide")
    terms = client.get("/terms")
    swagger = client.get("/docs")
    openapi = client.get("/openapi.json")
    signup = client.post("/api/v2/signup").json()
    client.cookies.set("blindport_token", signup["token"])
    dashboard = client.get("/dashboard")
    client.cookies.clear()
    client.post("/admin/login", data={"token": "TESTADMIN0000"})
    admin = client.get("/admin")

    for response in (landing, guide, terms, dashboard, admin):
        assert response.status_code == 200
        assert response.headers["Cache-Control"] == "no-store"
        inspected = _inspect(response.text)
        assert len(inspected.ids) == len(set(inspected.ids))
        assert inspected.scripts_without_src == 0
        assert inspected.style_elements == 0
        assert inspected.inline_attributes == []

    assert swagger.status_code == 200
    assert "Swagger UI" in swagger.text
    assert openapi.json()["info"]["version"] == "0.2.3"
    assert signup["account_id"] in dashboard.text
    assert "User #" not in dashboard.text
    assert "User</th>" not in admin.text
    assert "There is currently no fixed traffic limit" in terms.text
    assert "reasonable traffic, bandwidth, connection, or rate limits" in terms.text
    assert "application behavior, DNS history, headers" in terms.text
    assert "not eligible for a refund" in terms.text
    assert "cannot prevent those providers" in terms.text
    assert "not an anonymity network or censorship-resistance system" in terms.text
    assert "state-level adversary" in terms.text
    assert "Tor onion services" in terms.text
    assert "suitable mixnets" in terms.text
    assert "only the limited privacy benefits described above" in terms.text


def test_catalog_exposes_only_configured_managed_suffix_metadata(app_client) -> None:
    client, _ = app_client

    response = client.get("/api/v1/catalog")

    assert response.status_code == 200
    body = response.json()
    assert body["managed_suffixes"] == ["relay.test"]
    assert "relay_pool_domains" not in body
    assert "relay.test" in client.get("/").text


def test_onion_requests_use_host_appropriate_cookie_and_hsts_policy(
    app_client, monkeypatch
) -> None:
    from blindport.api import pages
    from blindport.config import EnvironmentMode

    client, _ = app_client
    onion = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaam2dqd.onion"
    monkeypatch.setattr(pages.settings, "ONION_HOST", onion)
    monkeypatch.setattr(pages.settings, "ENVIRONMENT", EnvironmentMode.PRODUCTION)

    onion_landing = client.get("/", headers={"Host": onion})
    clearnet_landing = client.get("/", headers={"Host": "blindport.test"})
    onion_login = client.post(
        "/admin/login",
        headers={"Host": onion},
        data={"token": "TESTADMIN0000"},
        follow_redirects=False,
    )

    assert 'data-cookie-secure="false"' in onion_landing.text
    assert "Strict-Transport-Security" not in onion_landing.headers
    assert 'data-cookie-secure="true"' in clearnet_landing.text
    assert "Strict-Transport-Security" in clearnet_landing.headers
    assert "Secure" not in onion_login.headers["Set-Cookie"]
    assert "Path=/admin" in onion_login.headers["Set-Cookie"]
    assert "SameSite=strict" in onion_login.headers["Set-Cookie"]
    assert "Max-Age=900" in onion_login.headers["Set-Cookie"]
