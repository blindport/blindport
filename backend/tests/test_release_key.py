"""Public release and vulnerability-reporting key behavior."""

from __future__ import annotations

import hashlib
from pathlib import Path

EXPECTED_SHA256 = "896bfe4ccedeecc182be897d262ab5292b15a100c0d531d6b69d0021d55efd89"
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def test_release_key_is_downloadable_with_explicit_pgp_headers(app_client) -> None:
    client, _ = app_client

    response = client.get("/release-key.asc")

    assert response.status_code == 200
    assert response.headers["Content-Type"] == "application/pgp-keys"
    assert response.headers["Content-Disposition"] == (
        'attachment; filename="blindport-release-key.asc"'
    )
    assert response.headers["Cache-Control"] == "public, max-age=3600, must-revalidate"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.content.startswith(b"-----BEGIN PGP PUBLIC KEY BLOCK-----")
    assert hashlib.sha256(response.content).hexdigest() == EXPECTED_SHA256

    head = client.head("/release-key.asc")
    assert head.status_code == 200
    assert head.content == b""
    assert head.headers["Content-Length"] == str(len(response.content))


def test_security_reporting_has_one_encrypted_email_channel() -> None:
    policy = (REPOSITORY_ROOT / "SECURITY.md").read_text()
    issue_config = (REPOSITORY_ROOT / ".github/ISSUE_TEMPLATE/config.yml").read_text()

    assert policy.count("security@blindport.com") == 1
    assert "support@blindport.com" not in policy
    assert "security/advisories/new" not in policy
    assert "Unencrypted reports and reports sent through other channels are not accepted." in policy
    assert "url: mailto:security@blindport.com" in issue_config
    assert "security/advisories/new" not in issue_config


def test_release_workflow_pins_primary_and_encryption_subkey_fingerprints() -> None:
    workflow = (REPOSITORY_ROOT / ".github/workflows/release.yaml").read_text()

    assert "18EDE4726C1414844923D6FF14EABFF739C16205" in workflow
    assert "1EFA5E7F8BC29A869CF53F2E91D63CDB51FEA639" in workflow
    assert "backend/src/blindport/public/blindport-release-key.asc" in workflow


def test_main_agent_image_channel_does_not_replace_latest_release() -> None:
    ci_workflow = (REPOSITORY_ROOT / ".github/workflows/ci.yaml").read_text()
    release_workflow = (REPOSITORY_ROOT / ".github/workflows/release.yaml").read_text()

    assert "github.ref == 'refs/heads/main'" in ci_workflow
    assert "needs: e2e" in ci_workflow
    assert "tags: ghcr.io/blindport/blindportd:main" in ci_workflow
    assert "ghcr.io/blindport/blindportd:latest" not in ci_workflow
    assert '--tag "$image:latest"' in release_workflow
