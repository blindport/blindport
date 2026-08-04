"""Dashboard client setup must be complete and specific to delivery modes."""

from __future__ import annotations

import html
import json
import os
import re
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
    token_command = _element_text(dashboard, "framedSetupCommand")
    config = json.loads(generated)

    assert "Framed tunnel" in dashboard
    assert "Install generated configuration" in dashboard
    assert config == {
        "version": 1,
        "mappings": [
            {
                "subscription_id": public_id,
                "upstream": "127.0.0.1:443",
                "http_challenge_upstream": "127.0.0.1:80",
            }
        ],
    }
    assert all("id" not in mapping for mapping in config["mappings"])
    assert str(internal_id) != config["mappings"][0]["subscription_id"]
    assert "wireGuardSetupCommand" not in dashboard

    command_lines = command.splitlines()
    assert command_lines[3] == (
        "cat > \"$HOME/.config/blindport/config.json\" <<'BLINDPORT_CONFIG'"
    )
    assert command_lines[-1] == "BLINDPORT_CONFIG"
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
    assert stat.S_IMODE(installed.stat().st_mode) == 0o600
    assert stat.S_IMODE(config_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE((home / ".local" / "state" / "blindport").stat().st_mode) == 0o700

    token_victim = tmp_path / "token-must-not-be-overwritten"
    token_victim.write_text("preserve token target", encoding="utf-8")
    (config_dir / "token").symlink_to(token_victim)
    token_result = subprocess.run(
        ["bash", "-eu", "-o", "pipefail", "-c", token_command],
        env={**os.environ, "HOME": str(home)},
        input="TEST-TOKEN\n",
        text=True,
        capture_output=True,
        check=False,
    )
    assert token_result.returncode == 0, token_result.stderr
    installed_token = config_dir / "token"
    assert not installed_token.is_symlink()
    assert installed_token.read_text(encoding="utf-8") == "TEST-TOKEN\n"
    assert token_victim.read_text(encoding="utf-8") == "preserve token target"
    assert stat.S_IMODE(installed_token.stat().st_mode) == 0o600


def test_generated_nonrelay_mappings_use_local_port_80(app_client) -> None:
    client, _ = app_client
    signup = client.post("/api/v2/signup").json()
    token = signup["token"]
    port_id = _create_subscription(client, token, "port", transport="tcp")
    ip_id = _create_subscription(client, token, "ip", delivery="framed")
    _set_status(port_id, SubscriptionStatus.ACTIVE)
    _set_status(ip_id, SubscriptionStatus.ACTIVE)

    config = json.loads(_element_text(_dashboard(client, token), "generatedClientConfig"))
    mappings = {mapping["subscription_id"]: mapping for mapping in config["mappings"]}
    assert mappings == {
        port_id: {"subscription_id": port_id, "upstream": "127.0.0.1:80"},
        ip_id: {"subscription_id": ip_id, "upstream": "127.0.0.1:80"},
    }


def test_setup_visibility_tracks_non_cancelled_delivery_modes(app_client) -> None:
    client, _ = app_client
    signup = client.post("/api/v2/signup").json()
    token = signup["token"]

    empty = _dashboard(client, token)
    assert "framedSetupCommand" not in empty
    assert "wireGuardSetupCommand" not in empty

    relay_id = _create_subscription(
        client,
        token,
        "relay",
        domain="mode.relay.test",
    )
    wireguard_id = _create_subscription(client, token, "ip", delivery="framed")
    _set_delivery(wireguard_id, DeliveryMode.WIREGUARD)
    pending = _dashboard(client, token)
    assert "framedSetupCommand" in pending
    assert "generatedClientConfig" not in pending
    assert "framedRunCommand" not in pending
    assert "wireGuardSetupCommand" in pending

    _set_status(relay_id, SubscriptionStatus.EXPIRED)
    _set_status(wireguard_id, SubscriptionStatus.CANCELLED)
    expired_framed = _dashboard(client, token)
    assert "framedSetupCommand" in expired_framed
    assert "generatedClientConfig" not in expired_framed
    assert "wireGuardSetupCommand" not in expired_framed

    _set_status(relay_id, SubscriptionStatus.CANCELLED)
    cancelled = _dashboard(client, token)
    assert "framedSetupCommand" not in cancelled
    assert "wireGuardSetupCommand" not in cancelled


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
    wireguard_id = _create_subscription(client, token, "ip", delivery="framed")
    _set_delivery(wireguard_id, DeliveryMode.WIREGUARD)
    _set_status(relay_id, SubscriptionStatus.ACTIVE)
    _set_status(wireguard_id, SubscriptionStatus.ACTIVE)

    dashboard = _dashboard(client, token)
    assert "framedConfigInstallCommand" in dashboard
    assert "framedRunCommand" in dashboard
    assert "wireGuardSetupCommand" in dashboard
    assert "wireGuardRunCommand" in dashboard
    for element_id in (
        "framedConfigInstallCommand",
        "framedSetupCommand",
        "framedRunCommand",
        "wireGuardSetupCommand",
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
