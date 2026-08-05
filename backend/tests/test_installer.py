"""The public installer must verify downloads before installing the agent."""

from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "scripts" / "install.sh"


def _fake_download_tools(
    tmp_path: Path, checksum: str, *, uid: int = 1000
) -> tuple[Path, Path, Path]:
    tools = tmp_path / "tools"
    tools.mkdir()
    payload = tmp_path / "blindportd-linux-amd64"
    payload.write_bytes(b"test blindport binary\n")
    checksum_file = tmp_path / "blindportd-linux-amd64.sha256"
    curl_log = tmp_path / "curl.log"
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
printf '%s\n' "$url" >> {curl_log}
case "$url" in
    *.sha256) cp {checksum_file} "$output" ;;
    *) cp {payload} "$output" ;;
esac
""",
        encoding="ascii",
    )
    (tools / "id").write_text(
        f"#!/bin/sh\n[ \"${{1:-}}\" = -u ] && printf '{uid}\\n'\n",
        encoding="ascii",
    )
    for tool in tools.iterdir():
        tool.chmod(0o755)
    return tools, payload, curl_log


def test_installer_verifies_and_installs_expected_architecture(tmp_path: Path) -> None:
    digest = hashlib.sha256(b"test blindport binary\n").hexdigest()
    tools, payload, _ = _fake_download_tools(tmp_path, digest)
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
    tools, _, _ = _fake_download_tools(tmp_path, "0" * 64)
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


def test_non_root_installs_locally_and_configures_bash_path_once(tmp_path: Path) -> None:
    digest = hashlib.sha256(b"test blindport binary\n").hexdigest()
    tools, payload, curl_log = _fake_download_tools(tmp_path, digest)
    home = tmp_path / "home"
    home.mkdir()
    profile = home / ".bashrc"
    profile.write_text("# existing settings\n", encoding="ascii")
    env = {
        **os.environ,
        "HOME": str(home),
        "SHELL": "/bin/bash",
        "PATH": f"{tools}:/usr/bin:/bin",
    }

    first = subprocess.run(
        ["sh", str(INSTALLER)],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    second = subprocess.run(
        ["sh", str(INSTALLER)],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    installed = home / ".local" / "bin" / "blindportd"
    assert first.returncode == second.returncode == 0
    assert installed.read_bytes() == payload.read_bytes()
    export = 'export PATH="$HOME/.local/bin:$PATH"'
    assert profile.read_text(encoding="ascii").splitlines().count(export) == 1
    assert f"Installed blindportd to {installed}" in first.stdout
    assert f"For this shell, run: {export}" in first.stdout
    assert "already configured" in second.stdout
    assert curl_log.read_text(encoding="ascii").splitlines()[:2] == [
        "https://blindport.com/downloads/blindportd-linux-amd64",
        "https://blindport.com/downloads/blindportd-linux-amd64.sha256",
    ]


def test_non_root_uses_zsh_profile_and_does_not_invoke_sudo(tmp_path: Path) -> None:
    digest = hashlib.sha256(b"test blindport binary\n").hexdigest()
    tools, _, _ = _fake_download_tools(tmp_path, digest)
    home = tmp_path / "home"
    home.mkdir()
    sudo_marker = tmp_path / "sudo-called"
    (tools / "sudo").write_text(f"#!/bin/sh\ntouch {sudo_marker}\nexit 99\n", encoding="ascii")
    (tools / "sudo").chmod(0o755)

    result = subprocess.run(
        ["sh", str(INSTALLER)],
        env={
            **os.environ,
            "HOME": str(home),
            "SHELL": "/usr/bin/zsh",
            "PATH": f"{tools}:/usr/bin:/bin",
        },
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert not sudo_marker.exists()
    assert (home / ".zshrc").read_text(encoding="ascii").count(".local/bin") == 1


def test_root_defaults_to_usr_local_without_changing_profile(tmp_path: Path) -> None:
    digest = hashlib.sha256(b"test blindport binary\n").hexdigest()
    tools, _, _ = _fake_download_tools(tmp_path, digest, uid=0)
    install_log = tmp_path / "install.log"
    (tools / "install").write_text(
        f"#!/bin/sh\nprintf '%s\\n' \"$*\" >> {install_log}\n",
        encoding="ascii",
    )
    (tools / "install").chmod(0o755)

    result = subprocess.run(
        ["sh", str(INSTALLER)],
        env={**os.environ, "PATH": f"{tools}:/usr/bin:/bin"},
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "Installed blindportd to /usr/local/bin/blindportd" in result.stdout
    assert "/usr/local/bin" in install_log.read_text(encoding="ascii")
    assert "command -v sudo" not in INSTALLER.read_text(encoding="ascii")
