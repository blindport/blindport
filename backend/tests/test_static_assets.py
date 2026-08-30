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


def _repository_file(name: str) -> str:
    return (Path(__file__).resolve().parents[2] / name).read_text(encoding="utf-8")


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
        "if (!legacyToken || setActive(legacyToken)) localStorage.removeItem(LEGACY_KEY)"
        in account_storage
    )
    assert "if (activeToken() === normalizedToken) clearActive()" in account_storage
    assert 'document.getElementById("savedAccountToken").value = account.token' in login
    assert "accounts.forget(account.token)" in login
    assert "!accounts.forget(account.token)" in login
    assert 'action="/login"' in _asset("templates/login.html")
    assert 'name="token"' in _asset("templates/login.html")
    assert 'document.getElementById("loginForm").addEventListener' in login
    assert "if (token) accounts.setActive(token)" in login
    assert "if (rejectedToken) accounts.forget(rejectedToken)" in login
    assert "Authorization" not in dashboard

    assert "billing_term: term" in dashboard
    assert 'delivery: product === "ip" ? "wireguard" : "framed"' in dashboard
    assert 'if (document.getElementById("product")?.value === "ip") return "yearly"' in dashboard
    assert (
        'document.getElementById("newOrderTerm")?.toggleAttribute("hidden", ipSelected)'
        in dashboard
    )
    assert "if (ipSelected && yearlyTerm) yearlyTerm.checked = true;" in dashboard
    assert "payment.period_days" in dashboard
    assert "payment.bonus_days" in dashboard
    assert "payment.stablecoin_surcharge_sats" in dashboard
    assert "payment.stablecoin_minimum_topup_sats" in dashboard
    assert 'name="orderBillingTerm"' in _asset("templates/landing.html")
    assert 'name="newBillingTerm"' in _asset("templates/dashboard.html")
    assert 'name="paymentTerm-{{ s.public_id }}"' in _asset("templates/dashboard.html")
    assert 'name="orderDelivery"' not in _asset("templates/landing.html")
    assert 'id="deliveryField"' not in _asset("templates/dashboard.html")
    assert 'id="delivery"' not in _asset("templates/dashboard.html")
    assert 'data-monthly-price="{{ ip.monthly_price_sats }}"' not in _asset(
        "templates/landing.html"
    )
    assert 'current.status === "paid"' in dashboard
    assert 'current.status === "expired"' in dashboard
    assert 'current.status === "failed"' in dashboard
    assert 'method === "stablecoin_swap"' in dashboard
    assert "payment.stablecoin_checkout_url" in dashboard
    assert "error.payload?.existing_payment" in dashboard
    assert "Continue with the existing checkout" in dashboard
    assert 'window.open("about:blank", "_blank")' not in dashboard
    assert "then select Check DNS before paying" in dashboard
    assert 'payUri.rel = "noopener noreferrer external"' in dashboard
    assert "verify-domain" in dashboard
    assert "Check DNS" in _asset("templates/dashboard.html")
    assert "Point this exact hostname to Blindport" in _asset("templates/dashboard.html")
    assert 'jsonFetch("/api/v1/payments"' in dashboard
    assert 'method: "DELETE"' in dashboard
    assert "domain_verification_token" in _asset("templates/dashboard.html")
    assert "accounts.save(activeToken, accountId)" in dashboard
    assert "accounts.clearActive()" in dashboard
    assert "accounts.forget(localToken)" in dashboard
    assert "if (!accounts.forget(localToken))" in dashboard
    assert 'window.location.assign("/dashboard")' in dashboard
    assert "accounts.copyText(localToken)" in dashboard
    assert "const button = event.currentTarget;" in dashboard
    assert 'button.textContent = copied ? "Copied"' in dashboard
    assert "JSON.stringify(body)" in dashboard
    assert 'product === "relay" ? selectedRelayHostnameScope() : "exact"' in landing
    assert 'product === "relay" ? selectedDashboardRelayHostnameScope() : "exact"' in dashboard
    assert "relay_scopes.exact.monthly_price_sats" in _asset("templates/landing.html")
    assert "relay_scopes.wildcard.monthly_price_sats" in _asset("templates/landing.html")
    assert "relay_scopes.exact.monthly_price_sats" in _asset("templates/dashboard.html")
    assert "relay_scopes.wildcard.monthly_price_sats" in _asset("templates/dashboard.html")
    assert "price includes the base hostname and wildcard descendants" in landing
    assert "price includes the base hostname and wildcard descendants" in dashboard
    assert "Wildcard price includes" in _asset("templates/landing.html")
    assert "Wildcard price includes" in _asset("templates/dashboard.html")
    assert "price includes <code>base</code> + <code>*.base</code>" in _asset(
        "templates/landing.html"
    )
    assert "price includes <code>base</code> + <code>*.base</code>" in _asset(
        "templates/dashboard.html"
    )
    assert "Routing record type" in _asset("templates/dashboard.html")
    assert "Only the TXT record is checked for ownership and payment." in _asset(
        "templates/dashboard.html"
    )
    assert "alongside existing SPF or site-verification TXT values" in _asset(
        "templates/dashboard.html"
    )
    assert "_blindport-challenge." not in _asset("templates/dashboard.html")
    assert "standard CNAME when the base is a subdomain" in _asset("templates/dashboard.html")
    assert "mandatory NS and SOA records prevent a conventional CNAME" in _asset(
        "templates/dashboard.html"
    )
    assert "ALIAS, ANAME, or CNAME-flattening feature" in _asset("templates/dashboard.html")
    assert "normally returns synthesized A and/or AAAA answers" in _asset(
        "templates/dashboard.html"
    )
    assert "Neither routing record is verified for payment." in _asset("templates/guide.html")
    assert "including a zone apex" in _asset("templates/guide.html")
    assert "`${body.domain} + *.${body.domain} (TLS passthrough)`" in landing
    assert "`${body.domain} (CNAME)`" in landing
    assert 'if (product === "ip") body.delivery = "wireguard"' in landing
    assert 'if (selectedProduct()?.value === "ip") return "yearly"' in landing
    assert "if (termControl) termControl.hidden = ipSelected;" in landing
    assert "if (ipSelected && yearly) yearly.checked = true;" in landing
    assert "monthly.disabled" not in landing
    assert "monthlyTerm.disabled" not in dashboard
    assert 'jsonFetch("/api/v1/me/notification-email"' in dashboard
    assert "/api/v1/me/reminder-email" not in dashboard
    assert "/api/v1/me/service-email" not in dashboard


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
    assert 'name="relayHostnameScope"' in landing
    assert 'name="dashboardRelayHostnameScope"' in dashboard
    assert (
        "Automatic HTTPS to a local plaintext app port for exact names; TLS passthrough for "
        "wildcard bases" in landing
    )
    assert 'id="accountToken" type="password" readonly' in dashboard
    assert 'id="copyInvoiceBtn"' in dashboard
    assert 'id="qrBox" role="img" aria-label="Lightning invoice QR code"' in dashboard
    assert 'id="stablecoinNotice"' in dashboard
    assert 'id="stablecoinInstructions"' in dashboard
    assert 'id="payInvoiceDetails"' in dashboard
    assert 'class="stablecoinPayBtn button-secondary"' in dashboard
    assert "install_script_url_shell" in dashboard
    assert "BLINDPORT_DOWNLOAD_BASE_URL=" not in dashboard
    assert "BLINDPORT_INSTALL_DIR=" not in dashboard
    assert 'id="acmeTermsAccepted" type="checkbox"' in dashboard
    assert "s.relay_hostname_scope.value != 'wildcard' else 'passthrough'" in dashboard
    assert "Wildcard Relay uses TLS passthrough" in dashboard
    assert "including a DNS zone apex" in dashboard
    assert (
        "local TLS listener and certificate must serve both the base and its descendant"
        in dashboard
    )
    assert 'class="mappingUpstream"' in dashboard
    assert 'class="copyCommandBtn configDependent"' in dashboard
    assert 'id="framedRunCommand"' in dashboard
    assert 'id="framedConfigInstallCommand"' in dashboard
    assert 'id="generatedClientConfig"' in dashboard
    assert 'id="notificationEmailForm"' in dashboard
    assert "user.has_notification_email" in dashboard
    assert "Most web services need a public hostname" in dashboard
    assert "One routed dedicated /32 over WireGuard, annual-only" in dashboard
    assert 'id="newOrderTerm"' in dashboard
    assert 'id="dashboardIpAnnualOnlyHint"' in dashboard
    assert "Service notifications" in dashboard
    assert (
        "Account lifecycle updates and service announcements use one email preference." in dashboard
    )
    assert "Relay HTTPS stays on your host" not in dashboard
    assert (
        "your agent terminates TLS and retains automatic certificate private keys while "
        "Blindport routes the connection." in dashboard
    )
    assert '<script src="/static/account-storage.js"></script>' in dashboard
    assert 'agree to the <a href="/terms">service terms</a>' in dashboard

    dashboard_script = _asset("static/dashboard.js")
    assert 'payment.stablecoin_provider === "lightning_swap"' in dashboard_script
    assert "This BOLT11 invoice is prefilled in Lightning Swap" in dashboard_script
    assert "Continue with Boltz to review the prefilled checkout." in dashboard_script

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
    assert admin.tables == 8
    assert admin.captions == admin.tables
    assert admin.unscoped_headers == 0
    assert admin.table_cells_without_labels == 0
    assert "row.account_public_id" in templates[4]
    assert "row.subscription_public_id" in templates[4]
    assert "account_by_user_id" not in templates[4]
    assert "{{ s.id }}" not in templates[4]
    assert "{{ p.subscription_id }}" not in templates[4]
    assert "{{ reminder.subscription_id }}" not in templates[4]


def test_content_covers_product_boundaries_and_client_operations() -> None:
    landing = _asset("templates/landing.html")
    guide = _asset("templates/guide.html")

    for term in (
        "CGNAT",
        "residential IP",
        "without publishing your residential IP",
        "Certificate keys and plaintext stay on your host",
        "Live pricing and availability",
        "Three steps, no inbound router changes",
        "TLS terminates on your host",
        "Automatic HTTPS to a local plaintext app port",
        "Different tools optimize for different jobs",
        "Quick preview tunnel",
        "Managed application gateway",
        "Community or self-hosted relay",
        "fully MIT-licensed, self-hostable stack",
        "routed public IPv4 /32",
        "best effort",
        "not an anonymity network",
        "Tor SOCKS5",
        "One routed dedicated /32 over WireGuard",
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
        "Configure local services",
        "persistent user service",
        "Docker socket warning",
        "Automatic HTTPS",
        "Routed WireGuard mode",
        "Tor SOCKS5 transport",
        "fails closed",
        "cannot be combined",
        "Troubleshooting",
        "Current limitations",
        "CAP_NET_ADMIN",
        "native UDP or ICMP semantics",
        "other IPv4 protocols",
        "ghcr.io/blindport/blindportd",
        "https://github.com/blindport/blindport/issues",
        '"upstream": "127.0.0.1:8080"',
        "blindportd -install-user-service",
        "blindportd -socks5=127.0.0.1:9050{{ backend_flag_shell }} -config=",
        '"version": 3',
        '"name": "public"',
        '"token_file": "/home/blindport/.config/blindport/tokens/public"',
        '"state_dir": "/home/blindport/.local/state/blindport-public"',
        'tech.blindport.mapping.web.account: "public"',
        "/opt/blindport/state:/var/lib/blindport",
        "GitHub Actions builds versioned static Linux binaries",
        "only detects transfer corruption",
        "does not authenticate the CI-built binary",
        "build the checked-out source locally",
        "GPG signature authenticates the source history, not GitHub-built artifacts",
        "Relay requires <code>.domain</code>",
        "<code>tcp</code> and <code>udp</code>",
        "Omit <code>.transport</code> for TCP and <code>.billing_term</code> for monthly billing",
        "Routed Blindport IP cannot be declared with Docker labels",
        "<code>payment_pending</code> means that payment is awaiting settlement or reconciliation",
        "<code>awaiting_payment</code>",
        "<code>awaiting_domain</code>",
        "exact DNS-only CNAME",
        "multi-account mappings must select one",
    ):
        assert term in guide
    run_section = guide.split('<section id="run">', 1)[1].split("</section>", 1)[0]
    assert '-config="$HOME/.config/blindport/config.json"</code>' in run_section
    assert "canonical, unique UUIDv4 values" in guide
    assert "BLINDPORT_DOWNLOAD_BASE_URL" not in guide
    assert "BLINDPORT_INSTALL_DIR" not in guide
    assert "BLINDPORT_BACKEND_URL" not in guide
    assert "${DOCKER_GID:-999}" in guide
    assert "Traefik" not in guide

    base = _asset("templates/base.html")
    assert "https://github.com/blindport/blindport" in base
    assert "https://github.com/blindport/blindport/issues" in base
    assert "/opt/blindport/config/config.json:/etc/blindport/config.json:ro" in guide
    assert "/opt/blindport/state:/var/lib/blindport" in guide
    assert "cap_add: [NET_ADMIN]" in guide
    assert "executable carries that file capability" in guide
    assert "runs as UID/GID <code>10001:10001</code>" in guide
    assert "mode <code>0600</code> on a directory omits the execute bit" in guide
    assert "Bind each token file separately" in guide
    assert "Do not bind the whole host secrets directory" in guide
    assert "readable token with broader permissions produces a warning" in guide


def test_agent_and_docker_examples_document_v3_token_files_and_boundaries() -> None:
    guide = _asset("templates/guide.html")
    agent = _repository_file("docs/agent.md")
    docker_readme = _repository_file("examples/docker/README.md")
    docker_compose = _repository_file("examples/docker/compose.yaml")
    docker_config = _repository_file("examples/docker/config/config.json")
    docker_env = _repository_file("examples/docker/.env.example")
    traefik_compose = _repository_file("examples/docker-traefik/compose.yaml")
    traefik_config = _repository_file("examples/docker-traefik/config/config.json")

    forbidden_rollout_term = "can" + "ary"
    for document in (
        guide,
        agent,
        docker_readme,
        docker_compose,
        docker_config,
        docker_env,
    ):
        assert forbidden_rollout_term not in document.lower()

    assert '"version": 3' in docker_config
    assert '"token_file": "/run/secrets/blindport-public"' in docker_config
    assert '"state_dir"' not in docker_config
    assert '"mappings"' not in docker_config
    assert "defaults to <code>/var/lib/blindport/accounts/&lt;account-name&gt;</code>" in guide
    assert "it is static and must define its own" in guide
    assert 'command: ["--docker", "--config=/etc/blindport/config.json"]' in docker_compose
    assert 'tech.blindport.mapping.site.account: "public"' not in docker_compose
    assert "labels use it automatically" in guide
    assert "BLINDPORT_TOKEN:" not in docker_compose
    assert "BLINDPORT_BACKEND_URL" not in docker_compose
    assert "${DOCKER_GID:-999}" in docker_compose
    assert "cap_drop: [ALL]" in docker_compose
    assert "cap_add: [NET_ADMIN]" in docker_compose
    assert "/opt/blindport/config/config.json:/etc/blindport/config.json:ro" in docker_compose
    assert "/opt/blindport/state:/var/lib/blindport" in docker_compose
    assert "/opt/blindport/secrets:/run/secrets" not in docker_compose
    assert "ipv4_address: 172.30.0.2" in docker_compose
    assert "BLINDPORT_BACKEND_URL" not in traefik_compose
    assert "${DOCKER_GID:-999}" in traefik_compose
    assert "cap_drop: [ALL]" in traefik_compose
    assert "cap_add: [NET_ADMIN]" in traefik_compose
    assert 'command: ["--docker", "--config=/etc/blindport/config.json"]' in traefik_compose
    assert "/opt/blindport/config/config.json:/etc/blindport/config.json:ro" in traefik_compose
    assert "/opt/blindport/traefik-acme:/letsencrypt" in traefik_compose
    assert "/opt/blindport/secrets:/run/secrets" not in traefik_compose
    assert traefik_config == docker_config
    assert "BLINDPORT_TOKEN=" not in docker_env
    assert "owner-only token file" in docker_readme
    assert "non-overlapping state directory" in docker_readme

    for term in (
        "stable, account-scoped order key",
        "payment_pending",
        "awaiting_payment",
        "awaiting_domain",
        "exact DNS-only CNAME",
        "does not cancel,\nrefund, or otherwise end the subscription",
        "two provider edges for resilience of new connections",
        "established\nconnections do not migrate",
        "not health steering",
        "no availability guarantee",
        "provider-specific",
        "website and control plane are\nnot an HA service",
        "previously issued paid framed\nauthorization",
        "not an\nextension of the paid term",
        "online denial",
    ):
        assert term in agent
    for term in (
        "separate agent process from Docker discovery",
        "active annual WireGuard Blindport IP subscription",
        "network_mode: host",
        "cap_add: [NET_ADMIN]",
        "only\nadditional container capability required",
        "root-owned regular file with mode `0600`",
        "remains root-owned",
        "Do not give this process the Docker\nsocket",
    ):
        assert term in agent


def test_migration_services_disable_external_delivery_and_signing() -> None:
    for path in (
        "deploy/production/compose.yaml",
        "deploy/split/control/compose.yaml",
    ):
        compose = _repository_file(path)
        assert 'REMINDER_EMAIL_ENABLED: "false"' in compose
        assert 'SMTP_USERNAME: ""' in compose
        assert 'SMTP_PASSWORD_FILE: ""' in compose
        assert 'OFFLINE_ENTITLEMENTS_ENABLED: "false"' in compose
        assert 'OFFLINE_ENTITLEMENT_PRIVATE_KEY_FILE: ""' in compose


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
    assert re.search(r"(?m)^\.admin-page \.section-heading \{ display: flex;", css)
    assert not re.search(r"(?m)^\.section-heading \{ display: flex;", css)
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
    assert (
        '<meta property="og:title" ' 'content="Blindport | Public ingress for self-hosters">'
    ) in response.text
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
    assert (
        '<meta property="og:title" content="Bridge | Public ingress for self-hosters">'
        in customized.text
    )
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
    assert openapi.json()["info"]["version"] == "0.3.0"
    assert signup["account_id"] in dashboard.text
    assert "User #" not in dashboard.text
    assert "User</th>" not in admin.text
    assert "There is currently no fixed traffic limit" in terms.text
    assert "Best-effort beta" in terms.text
    assert "does not persist visitor or request source IP addresses" in terms.text
    assert "deleted within 30 days" in terms.text
    assert "one routed dedicated /32 over WireGuard, annual-only for 365 days" in landing.text
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
        json={"product": "port", "transport": "tcp"},
        headers={"Authorization": f"Bearer {signup['token']}"},
    )

    disabled = client.get("/dashboard")
    monkeypatch.setattr(pages.settings, "STABLECOIN_PAYMENTS_ENABLED", True)
    enabled = client.get("/dashboard")

    assert "stablecoinPayBtn" not in disabled.text
    assert "stablecoinPayBtn" in enabled.text
    assert "Pay with stablecoin" in enabled.text


def test_dashboard_notification_control_follows_feature_gate_and_hides_address(
    app_client, monkeypatch
) -> None:
    from blindport import config

    client, _ = app_client
    signup = client.post("/api/v2/signup").json()
    headers = {"Authorization": f"Bearer {signup['token']}"}
    client.cookies.set("blindport_token", signup["token"])

    disabled = client.get("/dashboard")
    assert "notificationEmailForm" not in disabled.text

    monkeypatch.setattr(config.settings, "ANNOUNCEMENT_EMAIL_ENABLED", True)
    enabled = client.get("/dashboard")
    assert "notificationEmailForm" in enabled.text
    assert 'id="notificationEmailStatus" role="status" aria-live="polite">Disabled' in enabled.text
    assert "deleteNotificationEmailBtn" not in enabled.text

    address = "customer-announcement@example.com"
    saved = client.post("/api/v1/me/notification-email", json={"email": address}, headers=headers)
    assert saved.status_code == 200
    rendered = client.get("/dashboard")

    assert 'id="notificationEmailStatus" role="status" aria-live="polite">Enabled' in rendered.text
    assert "deleteNotificationEmailBtn" in rendered.text
    assert address not in rendered.text


def test_dashboard_service_notifications_render_one_form_when_either_category_is_enabled(
    app_client, monkeypatch
) -> None:
    from blindport import config

    client, _ = app_client
    signup = client.post("/api/v2/signup").json()
    client.cookies.set("blindport_token", signup["token"])

    disabled = client.get("/dashboard")
    assert "Service notifications" not in disabled.text
    assert "notificationEmailForm" not in disabled.text

    monkeypatch.setattr(config.settings, "REMINDER_EMAIL_ENABLED", True)
    updates_only = client.get("/dashboard")
    assert "Service notifications" in updates_only.text
    assert "notificationEmailForm" in updates_only.text
    assert "/api/v1/me/notification-email" in _asset("static/dashboard.js")

    monkeypatch.setattr(config.settings, "REMINDER_EMAIL_ENABLED", False)
    monkeypatch.setattr(config.settings, "ANNOUNCEMENT_EMAIL_ENABLED", True)
    announcements_only = client.get("/dashboard")
    assert "Service notifications" in announcements_only.text
    assert "notificationEmailForm" in announcements_only.text

    monkeypatch.setattr(config.settings, "REMINDER_EMAIL_ENABLED", True)
    both_enabled = client.get("/dashboard")
    assert both_enabled.text.count("<summary>Service notifications</summary>") == 1
    assert both_enabled.text.count('id="notificationEmailForm"') == 1


def test_landing_distinguishes_routed_ip_sale_states(app_client, monkeypatch) -> None:
    from blindport import config

    client, _ = app_client
    monkeypatch.setattr(config.settings, "IP_ENABLED", True)
    monkeypatch.setattr(config.settings, "IP_SALES_PAUSED", False)
    monkeypatch.setattr(config.settings, "WIREGUARD_PUBLIC_IPS", "198.51.100.20")
    monkeypatch.setattr(config.settings, "BILLING_YEARLY_ENABLED", False)
    annual_disabled = client.get("/")
    assert "Annual billing disabled" in annual_disabled.text
    assert "No free WireGuard inventory" not in annual_disabled.text

    monkeypatch.setattr(config.settings, "BILLING_YEARLY_ENABLED", True)
    monkeypatch.setattr(config.settings, "IP_SALES_PAUSED", True)
    sales_paused = client.get("/")
    assert "Sales paused" in sales_paused.text

    monkeypatch.setattr(config.settings, "IP_SALES_PAUSED", False)
    monkeypatch.setattr(config.settings, "WIREGUARD_PUBLIC_IPS", "")
    no_inventory = client.get("/")
    assert "No free WireGuard inventory" in no_inventory.text


def test_landing_ip_order_uses_annual_wireguard_only_metadata(app_client, monkeypatch) -> None:
    from blindport import config

    client, _ = app_client
    monkeypatch.setattr(config.settings, "IP_ENABLED", True)
    monkeypatch.setattr(config.settings, "IP_SALES_PAUSED", False)
    monkeypatch.setattr(config.settings, "WIREGUARD_PUBLIC_IPS", "198.51.100.20")
    monkeypatch.setattr(config.settings, "BILLING_YEARLY_ENABLED", True)

    landing = client.get("/")

    assert 'data-order-product="ip">Choose IP</a>' in landing.text
    assert 'name="orderProduct" value="ip" data-yearly-price=' in landing.text
    assert 'name="orderProduct" value="ip" data-monthly-price=' not in landing.text
    assert 'id="orderTermControl"' in landing.text
    assert 'id="ipAnnualOnlyHint" class="field-help" hidden' in landing.text
    assert "one routed dedicated /32 over WireGuard, annual-only for 365 days" in landing.text


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
        json={"product": "port", "transport": "tcp"},
        headers={"Authorization": f"Bearer {signup['token']}"},
    )
    client.cookies.set("blindport_token", signup["token"])
    dashboard = client.get("/dashboard")

    assert "Prices are denominated in Bitcoin (BTC)." in landing.text
    assert "One bitcoin is 100 million satoshis (sats)." in landing.text
    assert "about $48.00 USD" in landing.text
    assert 'data-btc-usd="64000"' in dashboard.text
    assert "about $0.96 USD" in dashboard.text


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
    clearnet_landing = client.get(
        "/?return=%2Fdashboard&mode=compact", headers={"Host": "blindport.test"}
    )
    clearnet_api = client.get("/api/v1/catalog", headers={"Host": "blindport.test"})
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
    assert "Onion-Location" not in onion_landing.headers
    assert 'data-cookie-secure="true"' in clearnet_landing.text
    assert '<meta property="og:url" content="https://blindport.test/">' in clearnet_landing.text
    assert "Strict-Transport-Security" in clearnet_landing.headers
    assert clearnet_landing.headers["Onion-Location"] == (
        f"http://{onion}/?return=%2Fdashboard&mode=compact"
    )
    assert "Onion-Location" not in clearnet_api.headers
    assert ">Onion</a>" not in clearnet_landing.text
    assert "Onion service:" not in clearnet_landing.text
    assert "framed tunnel control are also reachable" not in clearnet_landing.text
    assert f">{onion}</a>" not in clearnet_landing.text
    assert "Secure" not in onion_login.headers["Set-Cookie"]
    assert "Path=/admin" in onion_login.headers["Set-Cookie"]
    assert "SameSite=strict" in onion_login.headers["Set-Cookie"]
    assert "Max-Age=900" in onion_login.headers["Set-Cookie"]


def test_dashboard_nwc_setup_is_inline_without_rendering_wallet_secret(
    app_client,
) -> None:
    client, _ = app_client
    signup = client.post("/api/v2/signup").json()
    headers = {"Authorization": f"Bearer {signup['token']}"}
    subscription = client.post(
        "/api/v1/subscriptions",
        json={"product": "port", "transport": "tcp"},
        headers=headers,
    ).json()
    client.cookies.set("blindport_token", signup["token"])

    disconnected = client.get("/dashboard")

    assert disconnected.status_code == 200
    assert f'data-sub-id="{subscription["id"]}"' in disconnected.text
    assert "inline-nwc-form" in disconnected.text
    assert "Connect and pay" in disconnected.text
    assert "inlineNwcAutoRenew" in disconnected.text
    assert "Renew this endpoint automatically" in disconnected.text
    assert "complete connection URI" in disconnected.text
    assert "autoRenewToggle" not in disconnected.text

    secret = "nostr+walletconnect://backend-secret"
    connected = client.post(
        "/api/v1/me/nwc",
        json={"nwc_uri": secret},
        headers=headers,
    )
    assert connected.status_code == 200
    rendered = client.get("/dashboard")
    assert secret not in rendered.text
    assert "inline-nwc-form" not in rendered.text
    assert "Pay with connected wallet" in rendered.text
    assert "autoRenewToggle" not in rendered.text
