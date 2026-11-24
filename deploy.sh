#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
set -euo pipefail

PROJECT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REMOTE_DIR=reality-tools
SKIP_DEPS=0
SSH_TARGET=

usage() {
    cat <<'EOF'
Usage: bash deploy.sh [--dir PATH] [--skip-deps] USER@HOST

Upload the current project files over SSH and run install.sh on the server.
Uses your normal SSH keys, agent and ~/.ssh/config. Uncommitted files are included.

  --dir PATH   Remote project directory (default: reality-tools, relative to SSH home)
  --skip-deps  Check existing dependencies instead of installing packages
  -h, --help   Show this help

Project files in the target directory are replaced. Results and .git are untouched.
EOF
}

while (($#)); do
    case "$1" in
        --dir)
            (($# >= 2)) && [[ -n "$2" ]] || { printf '%s\n' '--dir requires a path.' >&2; exit 2; }
            REMOTE_DIR=$2
            shift
            ;;
        --skip-deps) SKIP_DEPS=1 ;;
        -h|--help) usage; exit 0 ;;
        -*) printf 'Unknown option: %s\n' "$1" >&2; exit 2 ;;
        *)
            [[ -z "$SSH_TARGET" ]] || { printf 'Specify one SSH target.\n' >&2; exit 2; }
            SSH_TARGET=$1
            ;;
    esac
    shift
done

if [[ -z "$SSH_TARGET" || "$SSH_TARGET" == *[[:space:]]* ]]; then
    usage >&2
    exit 2
fi
for tool in ssh tar mktemp; do
    command -v "$tool" >/dev/null 2>&1 || { printf 'Required tool not found: %s\n' "$tool" >&2; exit 1; }
done
# Keep the destination a literal path, including spaces and shell metacharacters.
shell_quote() { printf "'%s'" "${1//\'/\'\"\'\"\'}"; }
quoted_dir=$(shell_quote "$REMOTE_DIR")

archive=$(mktemp)
trap 'rm -f -- "$archive"' EXIT
tar -czf "$archive" -C "$PROJECT_DIR" -- \
    .gitattributes .gitignore LICENSE README.md README.ru.md \
    reality_sni_finder.py https_healthcheck.py install.sh run.sh deploy.sh \
    tests/test_shell_scripts.py

printf 'Uploading project to %s:%s ...\n' "$SSH_TARGET" "$REMOTE_DIR"
ssh -- "$SSH_TARGET" "set -eu; umask 022; mkdir -p -- $quoted_dir; tar -xzf - -C $quoted_dir" < "$archive"

install_command="cd -- $quoted_dir && bash install.sh"
if (( SKIP_DEPS )); then
    install_command+=' --skip-deps'
fi
# A TTY lets sudo ask for a password on the server, after the archive is transferred.
ssh -t -- "$SSH_TARGET" "$install_command"
printf '\nDeployment complete. Connect and open the menu:\n'
printf '  ssh -t %q %q\n' "$SSH_TARGET" "cd -- $quoted_dir && bash run.sh"
