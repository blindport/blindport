"""The public installer must verify downloads before installing the agent."""

from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "scripts" / "install.sh"


def _fake_download_tools(tmp_path: Path, checksum: str) -> tuple[Path, Path]:
    tools = tmp_path / "tools"
    tools.mkdir()
    payload = tmp_path / "blindportd-linux-amd64"
    payload.write_bytes(b"test blindport binary\n")
    checksum_file = tmp_path / "blindportd-linux-amd64.sha256"
    checksum_file.write_text(f"{checksum}  blindportd-linux-amd64\n", encoding="ascii")
    (tools / "uname").write_text(
        "#!/bin/sh\n[ \"${1:-}\" = -s ] && printf 'Linux\\n' || printf 'x86_64\\n'\n",
        encoding="ascii",
    )
    (tools / "curl").write_text(
        f"""#!/bin/sh
url=
output=
while [ "$#" -gt 0 ]; do
    case "$1" in
        -o) output=$2; shift 2 ;;
        https://*) url=$1; shift ;;
        *) shift ;;
    esac
done
case "$url" in
    *.sha256) cp {checksum_file} "$output" ;;
    *) cp {payload} "$output" ;;
esac
""",
        encoding="ascii",
    )
    for tool in tools.iterdir():
        tool.chmod(0o755)
    return tools, payload


def test_installer_verifies_and_installs_expected_architecture(tmp_path: Path) -> None:
    digest = hashlib.sha256(b"test blindport binary\n").hexdigest()
    tools, payload = _fake_download_tools(tmp_path, digest)
    destination = tmp_path / "install"
    result = subprocess.run(
        ["sh", str(INSTALLER)],
        env={
            **os.environ,
            "PATH": f"{tools}:{os.environ['PATH']}",
            "BLINDPORT_DOWNLOAD_BASE_URL": "https://downloads.example",
            "BLINDPORT_INSTALL_DIR": str(destination),
        },
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    installed = destination / "blindportd"
    assert installed.read_bytes() == payload.read_bytes()
    assert installed.stat().st_mode & 0o777 == 0o755
    assert f"Installed blindportd to {installed}" in result.stdout


def test_installer_rejects_checksum_mismatch(tmp_path: Path) -> None:
    tools, _ = _fake_download_tools(tmp_path, "0" * 64)
    destination = tmp_path / "install"
    result = subprocess.run(
        ["sh", str(INSTALLER)],
        env={
            **os.environ,
            "PATH": f"{tools}:{os.environ['PATH']}",
            "BLINDPORT_DOWNLOAD_BASE_URL": "https://downloads.example",
            "BLINDPORT_INSTALL_DIR": str(destination),
        },
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode != 0
    assert "checksum mismatch" in result.stderr
    assert not (destination / "blindportd").exists()
