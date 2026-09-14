#!/bin/sh
set -eu

download_base=${BLINDPORT_DOWNLOAD_BASE_URL:-https://blindport.com/downloads}
install_dir=${BLINDPORT_INSTALL_DIR:-}

for command in curl id install mktemp rm sha256sum uname; do
    command -v "$command" >/dev/null 2>&1 || {
        printf 'blindport installer: required command not found: %s\n' "$command" >&2
        exit 1
    }
done

case "$(uname -s):$(uname -m)" in
    Linux:x86_64|Linux:amd64) platform=linux-amd64 ;;
    Linux:aarch64|Linux:arm64) platform=linux-arm64 ;;
    Linux:armv7l|Linux:armv7) platform=linux-armv7 ;;
    *)
        printf 'blindport installer: unsupported platform %s %s\n' "$(uname -s)" "$(uname -m)" >&2
        exit 1
        ;;
esac

asset="blindportd-$platform"
temporary=$(mktemp -d "${TMPDIR:-/tmp}/blindport-install.XXXXXX")
curl_protocol='=https'
case "$download_base" in
    http://*.onion/*|http://*.onion:*/*) curl_protocol='=http,https' ;;
esac
cleanup() {
    rm -rf "$temporary"
}
trap cleanup EXIT HUP INT TERM

curl --fail --location --silent --show-error --proto "$curl_protocol" --tlsv1.2 \
    "$download_base/$asset" -o "$temporary/$asset"
curl --fail --location --silent --show-error --proto "$curl_protocol" --tlsv1.2 \
    "$download_base/$asset.sha256" -o "$temporary/$asset.sha256"

read -r expected_hash ignored < "$temporary/$asset.sha256"
case "$expected_hash" in
    *[!0-9a-f]*|'')
        printf 'blindport installer: invalid checksum file\n' >&2
        exit 1
        ;;
esac
[ "${#expected_hash}" -eq 64 ] || {
    printf 'blindport installer: invalid checksum length\n' >&2
    exit 1
}
actual_hash=$(sha256sum "$temporary/$asset")
actual_hash=${actual_hash%% *}
[ "$actual_hash" = "$expected_hash" ] || {
    printf 'blindport installer: checksum mismatch\n' >&2
    exit 1
}

user_install=false
if [ -n "$install_dir" ]; then
    install -d -m 0755 "$install_dir"
    install -m 0755 "$temporary/$asset" "$install_dir/blindportd"
    destination="$install_dir/blindportd"
elif [ "$(id -u)" -eq 0 ]; then
    install -d -m 0755 /usr/local/bin
    install -m 0755 "$temporary/$asset" /usr/local/bin/blindportd
    destination=/usr/local/bin/blindportd
else
    install_dir=${HOME:?HOME is required}/.local/bin
    install -d -m 0755 "$install_dir"
    install -m 0755 "$temporary/$asset" "$install_dir/blindportd"
    destination="$install_dir/blindportd"
    user_install=true
fi

printf 'Installed blindportd to %s\n' "$destination"
if [ "$user_install" = true ]; then
    case ":${PATH:-}:" in
        *":$install_dir:"*)
            printf '%s is already in PATH; run: blindportd\n' "$install_dir"
            ;;
        *)
            path_export='export PATH="$HOME/.local/bin:$PATH"'
            case "${SHELL:-}" in
                */zsh) profile=${ZDOTDIR:-$HOME}/.zshrc ;;
                */bash) profile=$HOME/.bashrc ;;
                *) profile=$HOME/.profile ;;
            esac
            found=false
            if [ -f "$profile" ]; then
                while IFS= read -r profile_line || [ -n "$profile_line" ]; do
                    if [ "$profile_line" = "$path_export" ]; then
                        found=true
                        break
                    fi
                done < "$profile"
            fi
            if [ "$found" = false ]; then
                printf '\n%s\n' "$path_export" >> "$profile"
                printf 'Added %s to %s\n' "$install_dir" "$profile"
            else
                printf '%s is already configured in %s\n' "$install_dir" "$profile"
            fi
            printf 'For this shell, run: %s\n' "$path_export"
            ;;
    esac
fi
printf 'Verify the installed release with: %s -version\n' "$destination"
printf 'Next, create the dashboard configuration and run blindportd beside your service or install its user service.\n'
