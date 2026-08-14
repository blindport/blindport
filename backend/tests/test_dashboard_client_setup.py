"""Dashboard client setup must be complete and specific to delivery modes."""

from __future__ import annotations

import html
import json
import os
import re
import shlex
import stat
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

from sqlmodel import Session, select

from blindport.core.models import DeliveryMode, Subscription, SubscriptionStatus


def _create_subscription(client, token: str, product: str, **extra: str) -> str:
    response = client.post(
        "/api/v1/subscriptions",
        headers={"Authorization": f"Bearer {token}"},
        json={"product": product, **extra},
    )
    assert response.status_code == 200, response.text
    return response.json()["id"]


def _set_status(public_id: str, status: SubscriptionStatus) -> int:
    from blindport.db import engine

    with Session(engine) as session:
        subscription = session.exec(
            select(Subscription).where(Subscription.public_id == UUID(public_id))
        ).one()
        subscription.status = status
        if status == SubscriptionStatus.ACTIVE:
            subscription.current_period_start = datetime.now(UTC)
            subscription.current_period_end = datetime.now(UTC) + timedelta(days=30)
        session.add(subscription)
        session.commit()
        assert subscription.id is not None
        return subscription.id


def _set_delivery(public_id: str, delivery: DeliveryMode) -> None:
    from blindport.db import engine

    with Session(engine) as session:
        subscription = session.exec(
            select(Subscription).where(Subscription.public_id == UUID(public_id))
        ).one()
        subscription.delivery = delivery
        session.add(subscription)
        session.commit()


def _element_text(document: str, element_id: str) -> str:
    match = re.search(
        rf'<code id="{re.escape(element_id)}">(.*?)</code>',
        document,
        flags=re.DOTALL,
    )
    assert match is not None, f"missing element {element_id}"
    return html.unescape(match.group(1))


def _dashboard(client, token: str) -> str:
    client.cookies.set("blindport_token", token)
    response = client.get("/dashboard")
    assert response.status_code == 200
    return response.text


def test_active_relay_command_installs_exact_private_config_without_wireguard(
    app_client, tmp_path: Path
) -> None:
    client, _ = app_client
    signup = client.post("/api/v2/signup").json()
    token = signup["token"]
    public_id = _create_subscription(
        client,
        token,
        "relay",
        domain="setup.relay.test",
    )
    internal_id = _set_status(public_id, SubscriptionStatus.ACTIVE)

    dashboard = _dashboard(client, token)
    generated = _element_text(dashboard, "generatedClientConfig")
    command = _element_text(dashboard, "framedConfigInstallCommand")
    install_command = _element_text(dashboard, "installAgentCommand")
    run_command = _element_text(dashboard, "framedRunCommand")
    config = json.loads(generated)

    assert "Framed tunnel" in dashboard
    assert "Review and install configuration" in dashboard
    assert 'class="disclosure-summary"' in dashboard
    assert "Copy JSON" in dashboard
    assert "Copy config install" in dashboard
    assert f"<dt>Subscription ID</dt><dd><code>{public_id}</code></dd>" in dashboard
    assert "prompts for your account token" in dashboard
    assert install_command == "curl -fsSL http://testserver/downloads/install.sh | sh"
    assert "BLINDPORT_DOWNLOAD_BASE_URL" not in dashboard
    assert "BLINDPORT_INSTALL_DIR" not in dashboard
    assert 'id="acmeTermsAccepted" type="checkbox"' in dashboard
    assert 'acmeTermsAccepted" type="checkbox" checked' not in dashboard
    assert (
        "For exact-name Blindport Relay, your agent terminates TLS and retains automatic "
        "certificate private keys while Blindport routes the connection." in dashboard
    )
    assert run_command == (
        'export PATH="$HOME/.local/bin:$PATH" && '
        "blindportd -backend=http://testserver "
        '-config="$HOME/.config/blindport/config.json"'
    )
    assert "-token-file" not in run_command
    assert config == {
        "version": 3,
        "accounts": [
            {
                "name": "default",
                "token_file": "/home/replace-me/.config/blindport/accounts/default.token",
                "state_dir": "/home/replace-me/.local/state/blindport/accounts/default",
                "mappings": [
                    {
                        "subscription_id": public_id,
                        "upstream": "127.0.0.1:8080",
                        "tls_mode": "automatic",
                        "acme_terms_accepted": False,
                    }
                ],
            }
        ],
    }
    mappings = config["accounts"][0]["mappings"]
    assert all("id" not in mapping for mapping in mappings)
    assert str(internal_id) != mappings[0]["subscription_id"]
    assert "wireGuardSetupCommand" not in dashboard

    command_lines = command.splitlines()
    assert command_lines[3] == ("cat > \"$temporary\" <<'BLINDPORT_CONFIG' &&")
    assert command_lines[-1] == ('mv -f -- "$temporary" "$HOME/.config/blindport/config.json"')
    assert token not in command
    assert token not in install_command
    assert token not in run_command
    syntax = subprocess.run(
        ["bash", "-n"],
        input=command,
        text=True,
        capture_output=True,
        check=False,
    )
    assert syntax.returncode == 0, syntax.stderr

    home = tmp_path / "home"
    config_dir = home / ".config" / "blindport"
    config_dir.mkdir(parents=True)
    victim = tmp_path / "must-not-be-overwritten"
    victim.write_text("preserve me", encoding="utf-8")
    (config_dir / "config.json").symlink_to(victim)
    result = subprocess.run(
        ["bash", "-eu", "-o", "pipefail", "-c", command],
        env={**os.environ, "HOME": str(home)},
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr

    installed = config_dir / "config.json"
    assert not installed.is_symlink()
    assert installed.read_text(encoding="utf-8") == f"{generated}\n"
    assert json.loads(installed.read_text(encoding="utf-8")) == config
    assert victim.read_text(encoding="utf-8") == "preserve me"
    assert (config_dir / "config.json.backup").read_text(encoding="utf-8") == "preserve me"
    assert stat.S_IMODE((config_dir / "config.json.backup").stat().st_mode) == 0o600
    assert stat.S_IMODE(installed.stat().st_mode) == 0o600
    assert stat.S_IMODE(config_dir.stat().st_mode) == 0o700


def test_dashboard_shell_quotes_request_origin_in_commands(app_client) -> None:
    client, _ = app_client
    signup = client.post("/api/v2/signup").json()
    public_id = _create_subscription(client, signup["token"], "port", transport="tcp")
    _set_status(public_id, SubscriptionStatus.ACTIVE)
    client.cookies.set("blindport_token", signup["token"])
    host = "control.example;id"

    response = client.get(f"http://{host}/dashboard")

    assert response.status_code == 200
    origin = f"http://{host}"
    assert _element_text(response.text, "installAgentCommand") == (
        f"curl -fsSL {shlex.quote(origin + '/downloads/install.sh')} | sh"
    )
    assert f"-backend={shlex.quote(origin)}" in _element_text(
        response.text, "installServiceCommand"
    )
    guide = html.unescape(client.get(f"http://{host}/guide").text)
    assert f"curl -fsSL {shlex.quote(origin + '/downloads/install.sh')} | sh" in guide
    assert f"BLINDPORT_BACKEND_URL: {json.dumps(origin)}" in guide
    assert f"sudo blindportd -wireguard -backend={shlex.quote(origin)}" in guide


def test_generated_nonrelay_mappings_use_passthrough_to_local_port_8080(app_client) -> None:
    client, _ = app_client
    signup = client.post("/api/v2/signup").json()
    token = signup["token"]
    port_id = _create_subscription(client, token, "port", transport="tcp")
    ip_id = _create_subscription(client, token, "ip")
    _set_delivery(ip_id, DeliveryMode.FRAMED)
    _set_status(port_id, SubscriptionStatus.ACTIVE)
    _set_status(ip_id, SubscriptionStatus.ACTIVE)

    config = json.loads(_element_text(_dashboard(client, token), "generatedClientConfig"))
    mappings = {
        mapping["subscription_id"]: mapping for mapping in config["accounts"][0]["mappings"]
    }
    assert mappings == {
        port_id: {
            "subscription_id": port_id,
            "upstream": "127.0.0.1:8080",
            "tls_mode": "passthrough",
        },
        ip_id: {
            "subscription_id": ip_id,
            "upstream": "127.0.0.1:8080",
            "tls_mode": "passthrough",
        },
    }

    dashboard = _dashboard(client, token)
    assert dashboard.index("Configure local targets") < dashboard.index(
        "Start the persistent service"
    )
    assert "systemctl --user status blindportd.service" in dashboard
    assert "journalctl --user -u blindportd.service -f" in dashboard
    assert "systemctl --user restart blindportd.service" in dashboard
    assert 'id="acmeTermsAccepted"' not in dashboard
    assert (
        "your agent terminates TLS and retains automatic certificate private keys" not in dashboard
    )
    assert f"<code>{port_id}</code>" in dashboard
    assert f"<code>{ip_id}</code>" in dashboard


def test_server_rendered_wildcard_relay_uses_passthrough_without_acme(app_client) -> None:
    client, _ = app_client
    signup = client.post("/api/v2/signup").json()
    token = signup["token"]
    public_id = _create_subscription(
        client,
        token,
        "relay",
        domain="rendered-wildcard.example",
        relay_hostname_scope="wildcard",
    )
    _set_status(public_id, SubscriptionStatus.ACTIVE)

    dashboard = _dashboard(client, token)
    config = json.loads(_element_text(dashboard, "generatedClientConfig"))

    assert "rendered-wildcard.example + *.rendered-wildcard.example" in dashboard
    assert 'id="acmeTermsAccepted"' not in dashboard
    assert "Wildcard Relay uses TLS passthrough" in dashboard
    assert "including a DNS zone apex" in dashboard
    assert (
        "local TLS listener and certificate must serve both the base and its descendant"
        in dashboard
    )
    assert config["accounts"][0]["mappings"] == [
        {
            "subscription_id": public_id,
            "upstream": "127.0.0.1:8080",
            "tls_mode": "passthrough",
        }
    ]


def test_setup_visibility_tracks_non_cancelled_delivery_modes(app_client) -> None:
    client, _ = app_client
    signup = client.post("/api/v2/signup").json()
    token = signup["token"]

    empty = _dashboard(client, token)
    assert "framedRunCommand" not in empty
    assert "wireGuardRunCommand" not in empty

    relay_id = _create_subscription(
        client,
        token,
        "relay",
        domain="mode.relay.test",
    )
    wireguard_id = _create_subscription(client, token, "ip")
    pending = _dashboard(client, token)
    assert "framedRunCommand" not in pending
    assert "generatedClientConfig" not in pending
    assert "wireGuardRunCommand" not in pending

    _set_status(relay_id, SubscriptionStatus.EXPIRED)
    _set_status(wireguard_id, SubscriptionStatus.CANCELLED)
    expired_framed = _dashboard(client, token)
    assert "framedRunCommand" not in expired_framed
    assert "generatedClientConfig" not in expired_framed
    assert "wireGuardRunCommand" not in expired_framed

    _set_status(relay_id, SubscriptionStatus.CANCELLED)
    cancelled = _dashboard(client, token)
    assert "framedRunCommand" not in cancelled
    assert "wireGuardRunCommand" not in cancelled


def test_mixed_active_modes_show_both_setup_workflows(app_client) -> None:
    client, _ = app_client
    signup = client.post("/api/v2/signup").json()
    token = signup["token"]
    relay_id = _create_subscription(
        client,
        token,
        "relay",
        domain="mixed.relay.test",
    )
    wireguard_id = _create_subscription(client, token, "ip")
    _set_status(relay_id, SubscriptionStatus.ACTIVE)
    _set_status(wireguard_id, SubscriptionStatus.ACTIVE)

    dashboard = _dashboard(client, token)
    assert "framedConfigInstallCommand" in dashboard
    assert "framedRunCommand" in dashboard
    assert "wireGuardRunCommand" in dashboard
    for element_id in (
        "framedConfigInstallCommand",
        "framedRunCommand",
        "wireGuardRunCommand",
    ):
        syntax = subprocess.run(
            ["bash", "-n"],
            input=_element_text(dashboard, element_id),
            text=True,
            capture_output=True,
            check=False,
        )
        assert syntax.returncode == 0, f"{element_id}: {syntax.stderr}"
