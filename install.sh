#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
set -euo pipefail

PROJECT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
SKIP_DEPS=0

usage() {
    cat <<'EOF'
Usage: bash install.sh [--skip-deps]

Install system dependencies on Debian/Ubuntu, then check this checkout.
No pip packages, services or scheduled tasks are installed.

  --skip-deps  Only check dependencies; do not run apt-get
  -h, --help   Show this help

Use PYTHON_BIN=/path/to/python3.11 to select a Python interpreter.
EOF
}

while (($#)); do
    case "$1" in
        --skip-deps) SKIP_DEPS=1 ;;
        -h|--help) usage; exit 0 ;;
        *) printf 'Unknown option: %s\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

if (( ! SKIP_DEPS )); then
    if [[ "$(uname -s)" != Linux ]] || ! command -v apt-get >/dev/null 2>&1; then
        printf 'Automatic installation requires Debian/Ubuntu with apt-get.\n' >&2
        printf 'Install Python 3.11+, git, masscan, curl, openssl and CA certificates, then use --skip-deps.\n' >&2
        exit 1
    fi
    elevate=()
    if (( EUID != 0 )); then
        command -v sudo >/dev/null 2>&1 || { printf 'Install dependencies as root or with sudo.\n' >&2; exit 1; }
        elevate=(sudo)
    fi
    "${elevate[@]}" apt-get update
    "${elevate[@]}" env DEBIAN_FRONTEND=noninteractive apt-get install -y \
        python3 git masscan curl openssl ca-certificates
fi

for script in run.sh deploy.sh install.sh; do
    chmod +x -- "$PROJECT_DIR/$script"
done
bash "$PROJECT_DIR/run.sh" check
printf '\nReady. Open the menu with:\n  bash %q\n' "$PROJECT_DIR/run.sh"
