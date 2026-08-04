"""Frontend structure and browser asset assertions without a browser dependency."""

from __future__ import annotations

import json
import re
from html.parser import HTMLParser
from pathlib import Path

import httpx

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


def _png_dimensions(content: bytes) -> tuple[int, int]:
    assert content[:8] == b"\x89PNG\r\n\x1a\n"
    assert content[12:16] == b"IHDR"
    return int.from_bytes(content[16:20]), int.from_bytes(content[20:24])


def _png_color_type(content: bytes) -> int:
    assert content[12:16] == b"IHDR"
    return content[25]


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
    assert 'method === "stablecoin_swap"' in dashboard
    assert "payment.stablecoin_checkout_url" in dashboard
    assert "error.payload?.existing_payment" in dashboard
    assert "Continue with the existing checkout" in dashboard
    assert 'window.open("about:blank", "_blank")' in dashboard
    assert 'payUri.rel = "noopener noreferrer external"' in dashboard
    assert "verify-domain" in dashboard
    assert "Check DNS" in _asset("templates/dashboard.html")
    assert "Point this exact hostname to Blindport" in _asset("templates/dashboard.html")
    assert 'jsonFetch("/api/v1/payments"' in dashboard
    assert 'method: "DELETE"' in dashboard
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
    assert '<img class="brand-mark" src="/static/brand-mark.svg"' in base
    assert '<link rel="icon" href="/static/favicon.ico"' in base
    assert '<link rel="icon" href="/static/brand-mark.svg"' in base
    assert '<link rel="apple-touch-icon" href="/static/apple-touch-icon.png"' in base
    assert '<link rel="manifest" href="/static/site.webmanifest">' in base
    assert '<meta property="og:image" content="{{ social_image_url }}">' in base
    assert '<meta name="twitter:card" content="{{ twitter_card }}">' in base

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
    assert "Enter the exact hostname to publish" in dashboard
    assert 'id="accountToken" type="password" readonly' in dashboard
    assert 'id="copyInvoiceBtn"' in dashboard
    assert 'id="qrBox" role="img" aria-label="Lightning invoice QR code"' in dashboard
    assert 'id="stablecoinNotice"' in dashboard
    assert 'class="stablecoinPayBtn button-secondary"' in dashboard
    assert "/downloads/install.sh | BLINDPORT_DOWNLOAD_BASE_URL=" in dashboard
    assert "BLINDPORT_INSTALL_DIR=" in dashboard
    assert 'id="framedRunCommand"' in dashboard
    assert 'id="framedConfigInstallCommand"' in dashboard
    assert 'id="generatedClientConfig"' in dashboard
    assert "Most web services need a public hostname" in dashboard
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

    assert landing.count('class="tls-path" role="img" aria-label=') == 1
    landing_inspector = _inspect(landing)
    assert landing_inspector.tables == 1
    assert landing_inspector.captions == 1
    assert landing_inspector.unscoped_headers == 0
    assert landing_inspector.table_cells_without_labels == 0

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
        "CGNAT",
        "residential IP",
        "A leased public endpoint",
        "Live pricing and availability",
        "Three steps, no inbound router changes",
        "Your certificate stays at the origin",
        "validated HTTP-01 requests",
        "Different tools optimize for different jobs",
        "Quick preview tunnel",
        "Managed application gateway",
        "Community or self-hosted relay",
        "fully MIT-licensed, self-hostable stack",
        "routed public IPv4 /32",
        "best effort",
        "not an anonymity network",
        "Tor SOCKS5",
        "One dedicated public IPv4",
        "One TCP or UDP socket",
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
        "-upstream=127.0.0.1:8080",
        "BLINDPORT_DOWNLOAD_BASE_URL=",
        "first-run input is the token prompt",
        'BLINDPORT_TOKEN: "${BLINDPORT_TOKEN:?set BLINDPORT_TOKEN}"',
        "blindport-state:/var/lib/blindport",
        "GitHub Actions builds versioned static Linux binaries",
        "only detects transfer corruption",
        "does not authenticate the CI-built binary",
        "build the checked-out source locally",
        "GPG signature authenticates the source history, not GitHub-built artifacts",
    ):
        assert term in guide
    run_section = guide.split('<section id="run">', 1)[1].split("</section>", 1)[0]
    assert '-config="$HOME/.config/blindport/config.json"</code>' not in run_section
    assert "canonical, unique UUIDv4 values" in guide

    base = _asset("templates/base.html")
    assert "https://github.com/blindport/blindport" in base
    assert "https://github.com/blindport/blindport/issues" in base
    assert "- blindport-state:/var/lib/blindport" in guide
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
    assert ".tls-path" in css
    assert "clip-path: polygon(0 0, 100% 50%, 0 100%)" in css
    assert 'content: ""' in css
    assert ".dashboard-grid" in css
    assert ".dashboard-sidebar" in css
    assert "overflow-x: clip" in css
    assert "a { color: var(--accent-dark); overflow-wrap: anywhere; }" in css
    assert "linear-gradient" not in css
    assert "radial-gradient" not in css
    assert "--radius: 4px" in css


def test_brand_assets_have_expected_formats_and_dimensions(app_client) -> None:
    client, _ = app_client
    package = Path(blindport.__file__).parent

    expected_pngs = {
        "apple-touch-icon.png": ((180, 180), 2),
        "brand-avatar.png": ((512, 512), 6),
        "brand-icon-192.png": ((192, 192), 2),
        "brand-icon-512.png": ((512, 512), 2),
        "brand-social.png": ((1200, 630), 2),
    }
    for name, (dimensions, color_type) in expected_pngs.items():
        content = (package / "static" / name).read_bytes()
        assert _png_dimensions(content) == dimensions
        assert _png_color_type(content) == color_type
        response = client.get(f"/static/{name}")
        assert response.status_code == 200
        assert response.headers["content-type"] == "image/png"

    for name in (
        "brand-app-icon.svg",
        "brand-mark.svg",
        "brand-social.svg",
        "brand-wordmark.svg",
    ):
        response = client.get(f"/static/{name}")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("image/svg+xml")
        assert response.text.startswith("<svg")

    app_icon_source = (package / "static" / "brand-app-icon.svg").read_text(encoding="utf-8")
    assert '<g transform="translate(71.68 71.68) scale(.72)">' in app_icon_source
    assert 'transform="translate(-6 -32)"' in app_icon_source
    assert "#21a981" not in app_icon_source
    mark_source = (package / "static" / "brand-mark.svg").read_text(encoding="utf-8")
    assert 'transform="translate(-6 -32)"' in mark_source
    assert "#21a981" not in mark_source

    favicon = client.get("/static/favicon.ico")
    assert favicon.status_code == 200
    assert favicon.headers["content-type"] == "image/vnd.microsoft.icon"
    assert favicon.content.startswith(b"\x00\x00\x01\x00")

    manifest = client.get("/static/site.webmanifest")
    assert manifest.status_code == 200
    assert manifest.headers["content-type"] == "application/manifest+json"
    assert json.loads(manifest.text)["icons"] == [
        {
            "src": "/static/brand-icon-192.png",
            "sizes": "192x192",
            "type": "image/png",
            "purpose": "any maskable",
        },
        {
            "src": "/static/brand-icon-512.png",
            "sizes": "512x512",
            "type": "image/png",
            "purpose": "any maskable",
        },
    ]


def test_share_metadata_uses_configured_origin_and_raster_card(app_client, monkeypatch) -> None:
    from blindport.api import pages

    client, _ = app_client
    monkeypatch.setattr(pages.settings, "PUBLIC_SITE_URL", "https://blindport.test")

    response = client.get("/?source=private", headers={"Host": "attacker.test"})

    assert response.status_code == 200
    assert (
        '<meta name="description" content="Public reach for self-hosted services.' in response.text
    )
    assert '<meta property="og:title" content="Blindport">' in response.text
    assert '<meta property="og:type" content="website">' in response.text
    assert '<meta property="og:url" content="https://blindport.test/">' in response.text
    assert (
        '<meta property="og:image" content="https://blindport.test/static/brand-social.png">'
    ) in response.text
    assert "attacker.test" not in response.text
    assert "source=private" not in response.text
    assert '<meta property="og:image:width" content="1200">' in response.text
    assert '<meta property="og:image:height" content="630">' in response.text
    assert '<meta name="twitter:card" content="summary_large_image">' in response.text

    guide = client.get("/guide")
    assert '<meta property="og:title" content="Guide | Blindport">' in guide.text
    assert (
        '<meta name="description" '
        'content="Install and operate Blindport for public access to self-hosted services.">'
    ) in guide.text

    login = client.get("/dashboard")
    assert '<meta name="robots" content="noindex, nofollow">' in login.text
    assert 'property="og:image"' not in login.text

    monkeypatch.setattr(pages.settings, "BRAND_NAME", "Bridge")
    monkeypatch.setattr(pages.settings, "BRAND_TAGLINE", "Public ingress for private origins.")
    customized = client.get("/")
    assert '<meta property="og:title" content="Bridge">' in customized.text
    assert (
        '<meta property="og:image" content="https://blindport.test/static/brand-avatar.png">'
    ) in customized.text
    assert '<meta name="twitter:card" content="summary">' in customized.text
    assert '<meta property="og:image:alt" content="Geometric B mark.">' in customized.text
    assert '<link rel="manifest" href="/static/site.webmanifest">' not in customized.text
    assert "Public ingress for private origins." in customized.text
    assert "Public reach for self-hosted services.</span>" not in customized.text
    assert "Blindport. Public reach" not in customized.text


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
    assert "Best-effort beta" in terms.text
    assert "does not persist visitor or request source IP addresses" in terms.text
    assert "deleted within 30 days" in terms.text
    assert "Fixed 30 or 365 days" in landing.text
    assert "reasonable traffic, bandwidth, connection, or rate limits" in terms.text
    assert "application behavior, DNS history, headers" in terms.text
    assert "not eligible for a refund" in terms.text
    assert "cannot prevent those providers" in terms.text
    assert "not an anonymity network or censorship-resistance system" in terms.text
    assert "state-level adversary" in terms.text
    assert "Tor onion services" in terms.text
    assert "suitable mixnets" in terms.text
    assert "only the limited privacy benefits described above" in terms.text


def test_dashboard_stablecoin_control_follows_feature_kill_switch(app_client, monkeypatch) -> None:
    from blindport.api import pages

    client, _ = app_client
    signup = client.post("/api/v2/signup").json()
    client.cookies.set("blindport_token", signup["token"])
    client.post(
        "/api/v1/subscriptions",
        json={"product": "ip"},
        headers={"Authorization": f"Bearer {signup['token']}"},
    )

    disabled = client.get("/dashboard")
    monkeypatch.setattr(pages.settings, "STABLECOIN_PAYMENTS_ENABLED", True)
    enabled = client.get("/dashboard")

    assert "stablecoinPayBtn" not in disabled.text
    assert "stablecoinPayBtn" in enabled.text
    assert "Pay with stablecoin" in enabled.text


def test_pages_explain_bitcoin_and_show_cached_approximate_usd(app_client, monkeypatch) -> None:
    from blindport.api import pages

    client, _ = app_client
    monkeypatch.setattr(pages.settings, "BTC_USD_PRICE_ENABLED", True)
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            200,
            json={"time": 1_785_859_508, "USD": 64_000},
            request=request,
        )
    )
    with httpx.Client(transport=transport) as price_client:
        pages.price_cache.refresh(price_client)

    landing = client.get("/")
    signup = client.post("/api/v2/signup").json()
    client.post(
        "/api/v1/subscriptions",
        json={"product": "ip"},
        headers={"Authorization": f"Bearer {signup['token']}"},
    )
    client.cookies.set("blindport_token", signup["token"])
    dashboard = client.get("/dashboard")

    assert "Prices are denominated in Bitcoin (BTC)." in landing.text
    assert "One bitcoin is 100 million satoshis (sats)." in landing.text
    assert "about $4.80 USD" in landing.text
    assert 'data-btc-usd="64000"' in dashboard.text
    assert "about $4.80 USD" in dashboard.text


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
    monkeypatch.setattr(pages.settings, "PUBLIC_SITE_URL", "https://blindport.test")
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
    assert f'<meta property="og:url" content="http://{onion}/">' in onion_landing.text
    assert (
        f'<meta property="og:image" content="http://{onion}/static/brand-social.png">'
    ) in onion_landing.text
    assert "Strict-Transport-Security" not in onion_landing.headers
    assert 'data-cookie-secure="true"' in clearnet_landing.text
    assert '<meta property="og:url" content="https://blindport.test/">' in clearnet_landing.text
    assert "Strict-Transport-Security" in clearnet_landing.headers
    assert "Secure" not in onion_login.headers["Set-Cookie"]
    assert "Path=/admin" in onion_login.headers["Set-Cookie"]
    assert "SameSite=strict" in onion_login.headers["Set-Cookie"]
    assert "Max-Age=900" in onion_login.headers["Set-Cookie"]
