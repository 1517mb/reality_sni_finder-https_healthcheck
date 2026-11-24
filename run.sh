#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
set -uo pipefail

PROJECT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
RESULTS_DIR="${RSF_RESULTS_DIR:-$PROJECT_DIR/results}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
MENU_LANG="${RSF_LANG:-${LC_ALL:-${LC_MESSAGES:-${LANG:-en}}}}"
cd -- "$PROJECT_DIR" || exit 1

msg() {
    if [[ "$MENU_LANG" == ru* ]]; then printf '%s' "$2"; else printf '%s' "$1"; fi
}

usage() {
    cat <<'EOF'
Usage: bash run.sh [menu|check|finder|healthcheck] [PYTHON_OPTIONS...]

  menu         Interactive menu with the project logo (default)
  check        Check dependencies without network requests
  finder       Run reality_sni_finder.py; uses sudo when required
  healthcheck  Run https_healthcheck.py as the current user
  -h, --help   Show this help

Python options are passed unchanged, including --help and --output.
Finder's default output: results/domains.txt. Healthcheck defaults to stdout.
Environment: PYTHON_BIN, RSF_LANG=ru|en, RSF_RESULTS_DIR.
Relative paths are resolved from the project directory.
EOF
}

require_python() {
    if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
        printf 'Python not found: %s\n' "$PYTHON_BIN" >&2
        return 1
    fi
    if ! "$PYTHON_BIN" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)'; then
        printf 'Python 3.11+ required. Set PYTHON_BIN to a suitable interpreter.\n' >&2
        return 1
    fi
}

check_dependencies() {
    local failed=0 tool curl_info
    if require_python; then
        "$PYTHON_BIN" --version
        if ! "$PYTHON_BIN" -c 'import ssl, sys; sys.exit(0 if ssl.HAS_TLSv1_3 else 1)'; then
            printf '[FAIL] Python SSL does not support TLS 1.3.\n' >&2
            failed=1
        fi
    else
        failed=1
    fi
    for tool in masscan curl openssl; do
        if command -v "$tool" >/dev/null 2>&1; then
            printf '[ OK ] %s: %s\n' "$tool" "$(command -v "$tool")"
        else
            printf '[FAIL] Missing: %s\n' "$tool" >&2
            failed=1
        fi
    done
    if command -v curl >/dev/null 2>&1; then
        curl_info=$(curl --disable --version) || return 1
        if [[ "$curl_info" =~ (^|[[:space:]])HTTP2([[:space:]]|$) ]]; then
            printf '[ OK ] curl HTTP/2 support\n'
        else
            printf '[FAIL] curl must be built with HTTP/2 support for Finder.\n' >&2
            failed=1
        fi
    fi
    return "$failed"
}

has_help() {
    local arg
    for arg in "$@"; do
        [[ "$arg" != --help && "$arg" != -h ]] || return 0
    done
    return 1
}

run_finder() {
    require_python || return 1
    local python_path
    python_path=$(command -v "$PYTHON_BIN") || return 1
    if has_help "$@"; then
        "$python_path" "$PROJECT_DIR/reality_sni_finder.py" "$@"
        return $?
    fi
    mkdir -p -- "$RESULTS_DIR" || return 1
    if (( EUID == 0 )); then
        "$python_path" "$PROJECT_DIR/reality_sni_finder.py" --output "$RESULTS_DIR/domains.txt" "$@"
    else
        command -v sudo >/dev/null 2>&1 || { printf 'Finder requires sudo or a root session.\n' >&2; return 1; }
        sudo -- "$python_path" "$PROJECT_DIR/reality_sni_finder.py" --output "$RESULTS_DIR/domains.txt" "$@"
    fi
}

run_healthcheck() {
    require_python || return 1
    "$PYTHON_BIN" "$PROJECT_DIR/https_healthcheck.py" "$@"
}

prompt() {
    local default=${3:-}
    msg "$1" "$2"
    [[ -z "$default" ]] || printf ' [%s]' "$default"
    printf ': '
    read -r MENU_INPUT || return 1
    MENU_INPUT=${MENU_INPUT%$'\r'}
    MENU_INPUT=${MENU_INPUT:-$default}
}

prompt_number() {
    local en=$1 ru=$2 default=$3 minimum=$4 maximum=$5
    while :; do
        prompt "$en" "$ru" "$default" || return 1
        # Limit length before arithmetic to avoid integer overflow from user input.
        if [[ "$MENU_INPUT" =~ ^[0-9]{1,6}$ ]] && (( 10#$MENU_INPUT >= minimum && 10#$MENU_INPUT <= maximum )); then
            MENU_INPUT=$((10#$MENU_INPUT))
            return 0
        fi
        msg "Enter an integer from $minimum to $maximum." "Введите целое число от $minimum до $maximum."
        printf '\n'
    done
}

confirm_authorized() {
    prompt 'I am authorized to test this domain/range. Continue? y/N' \
        'У меня есть разрешение на проверку домена/диапазона. Продолжить? y/N' n || return 1
    [[ "$MENU_INPUT" == y || "$MENU_INPUT" == Y ]]
}

menu_finder() {
    local ref_ip blocks rate top
    local args=()
    prompt 'Reference IPv4 (empty = autodetect)' 'Опорный IPv4 (пусто = автоопределение)' || return 0
    ref_ip=$MENU_INPUT
    if [[ -n "$ref_ip" ]]; then
        require_python || return 1
        if ! "$PYTHON_BIN" -c 'import ipaddress, sys; sys.exit(0 if ipaddress.ip_address(sys.argv[1]).version == 4 else 1)' "$ref_ip" 2>/dev/null; then
            msg 'Invalid IPv4 address.' 'Некорректный IPv4-адрес.'; printf '\n'; return 2
        fi
        args+=(--ref-ip "$ref_ip")
    fi
    prompt_number 'Neighbor /24s on EACH side (0 = one /24)' 'Соседних /24 с КАЖДОЙ стороны (0 = одна /24)' 0 0 256 || return 0
    blocks=$MENU_INPUT
    prompt_number 'masscan packets/s' 'Пакетов masscan в секунду' 4000 1 999999 || return 0
    rate=$MENU_INPUT
    prompt_number 'Maximum domains to save' 'Максимум доменов в результате' 30 1 10000 || return 0
    top=$MENU_INPUT
    confirm_authorized || return 0
    run_finder "${args[@]}" --blocks "$blocks" --rate "$rate" --top "$top" --verbose
}

menu_healthcheck() {
    local domain timeout report
    local args=(--authorized)
    prompt 'Domain (ASCII/Punycode, without https://)' 'Домен (ASCII/Punycode, без https://)' || return 0
    domain=$MENU_INPUT
    [[ -n "$domain" ]] || return 0
    prompt 'Also send an HTTPS HEAD request? Y/n' 'Дополнительно выполнить HTTPS HEAD? Y/n' y || return 0
    case "$MENU_INPUT" in y|Y) args+=(--http) ;; n|N) ;; *) return 2 ;; esac
    prompt_number 'Timeout per stage, seconds' 'Тайм-аут каждого этапа, с' 8 2 30 || return 0
    timeout=$MENU_INPUT
    confirm_authorized || return 0
    mkdir -p -- "$RESULTS_DIR" || return 1
    report="$RESULTS_DIR/healthcheck-$(date -u +%Y%m%dT%H%M%SZ)-${RANDOM}.json"
    printf '%s\n' "$report"
    run_healthcheck "${args[@]}" --timeout "$timeout" --output "$report" "$domain"
}

show_menu() {
    local choice result
    while :; do
        if [[ -t 1 && "${TERM:-dumb}" != dumb ]]; then printf '\033[2J\033[H'; fi
        cat <<'EOF'
  ____  _____    _    _     ___ _______   __
 |  _ \| ____|  / \  | |   |_ _|_   _\ \ / /
 | |_) |  _|   / _ \ | |    | |  | |  \ V /
 |  _ <| |___ / ___ \| |___ | |  | |   | |
 |_| \_\_____/_/   \_\_____|___| |_|   |_|

          SNI FINDER + HTTPS HEALTHCHECK
                     GPLv3
EOF
        printf '\n'
        printf '  1) '; msg 'Find SNI candidates' 'Найти SNI-кандидатов'; printf '\n'
        printf '  2) '; msg 'Check HTTPS domain' 'Проверить HTTPS-домен'; printf '\n'
        printf '  3) '; msg 'Check dependencies' 'Проверить зависимости'; printf '\n'
        printf '  4) English / Русский\n'
        printf '  0) '; msg 'Exit' 'Выход'; printf '\n\n'
        prompt 'Select' 'Выберите пункт' || return 0
        choice=$MENU_INPUT
        result=0
        case "$choice" in
            1) menu_finder; result=$? ;;
            2) menu_healthcheck; result=$? ;;
            3) check_dependencies; result=$? ;;
            4) if [[ "$MENU_LANG" == ru* ]]; then MENU_LANG=en; else MENU_LANG=ru; fi; continue ;;
            0) return 0 ;;
            *) msg 'Unknown menu item.' 'Неизвестный пункт меню.'; printf '\n'; continue ;;
        esac
        if (( result != 0 )); then
            msg "Command exited with code $result." "Команда завершилась с кодом $result."
            printf '\n'
        fi
        prompt 'Press Enter to return to the menu' 'Нажмите Enter для возврата в меню' || return 0
    done
}

command=${1:-menu}
if (($#)); then shift; fi
case "$command" in
    menu) (($# == 0)) || { usage >&2; exit 2; }; show_menu ;;
    check) (($# == 0)) || { usage >&2; exit 2; }; check_dependencies ;;
    finder) run_finder "$@" ;;
    healthcheck) run_healthcheck "$@" ;;
    -h|--help) usage ;;
    *) usage >&2; exit 2 ;;
esac
