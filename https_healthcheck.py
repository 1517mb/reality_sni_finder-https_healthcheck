#!/usr/bin/env python3
"""Проверка TLS-сертификата одного разрешённого HTTPS-домена.

Python 3.11+. Для дополнительной проверки HTTP нужен curl из доверенного
источника. Никаких диапазонов IP, поиска доменов, подмены DNS/SNI или root.

Пример (замените имя на домен, который вы администрируете):
    python3 https_healthcheck.py --authorized my-domain.example
    python3 https_healthcheck.py --authorized --http --output report.json my-domain.example

Коды завершения: 0 — проверка выполнена; 1 — ошибка диагностики;
2 — неверные аргументы; 3 — ошибка записи отчёта.
Предупреждение о скором истечении сертификата не считается ошибкой.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import multiprocessing as mp
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
from datetime import datetime, timezone


PORT = 443
DEFAULT_TIMEOUT = 8
WARN_DAYS = 30
LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.ASCII)


def hostname(value: str) -> str:
    """Принимается только конкретное DNS-имя в ASCII/Punycode."""
    if not value or value != value.strip() or not value.isascii():
        raise argparse.ArgumentTypeError("Введите DNS-имя в ASCII/Punycode без пробелов.")
    name = value.lower().removesuffix(".")
    labels = name.split(".")
    try:
        ipaddress.ip_address(name)
    except ValueError:
        pass
    else:
        raise argparse.ArgumentTypeError("IP-адреса и диапазоны не поддерживаются.")
    if (
        len(name) > 253
        or len(labels) < 2
        or not all(LABEL.fullmatch(label) for label in labels)
        or not ("a" <= labels[-1][0] <= "z")
    ):
        raise argparse.ArgumentTypeError(
            "Нужно указать одно доменное имя, без схемы, порта, пути или wildcard."
        )
    return name


def timeout_value(value: str) -> int:
    try:
        seconds = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Тайм-аут должен быть целым числом секунд.") from exc
    if not 2 <= seconds <= 30:
        raise argparse.ArgumentTypeError("Тайм-аут должен быть от 2 до 30 секунд.")
    return seconds


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_time(value: datetime) -> str:
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def failure(kind: str, message: object, verified: bool | None = None) -> dict:
    return {
        "status": "error",
        "certificate_verified": verified,
        "error_type": kind,
        "error": str(message)[:500],
    }


def check_certificate(name: str, timeout: int) -> dict:
    """Обычное TLS-соединение с проверкой цепочки доверия и имени хоста."""
    try:
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.hostname_checks_common_name = False  # Идентичность сервера подтверждает SAN.
        with socket.create_connection((name, PORT), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=name) as secure:
                cert = secure.getpeercert()
    except ssl.SSLCertVerificationError as exc:
        return failure("certificate_verification", exc, verified=False)
    except socket.gaierror as exc:
        return failure("dns", exc)
    except TimeoutError as exc:
        return failure("network_timeout", exc)
    except ssl.SSLError as exc:
        return failure("tls", exc)
    except OSError as exc:
        return failure("network", exc)

    try:
        end = datetime.fromtimestamp(
            ssl.cert_time_to_seconds(cert["notAfter"]), tz=timezone.utc
        )
    except (KeyError, TypeError, ValueError, OverflowError, OSError) as exc:
        return failure("certificate_metadata", exc, verified=True)

    remaining = (end - utc_now()).total_seconds() / 86400
    return {
        "status": "warning" if remaining <= WARN_DAYS else "ok",
        "certificate_verified": True,
        "expires_at_utc": iso_time(end),
        "days_remaining": round(remaining, 2),
        "expiry_warning": remaining <= WARN_DAYS,
    }


def _certificate_worker(sender, name: str, timeout: int) -> None:
    # SSLKEYLOGFILE не нужен для диагностики; меняем только среду дочернего процесса.
    os.environ.pop("SSLKEYLOGFILE", None)
    try:
        try:
            result = check_certificate(name, timeout)
        except Exception as exc:
            result = failure("internal", f"{type(exc).__name__}: {exc}")
        sender.send(result)
    except (BrokenPipeError, EOFError, OSError):
        # Родитель уже прекратил ожидание (тайм-аут или отмена).
        pass
    finally:
        sender.close()


def certificate_with_deadline(name: str, timeout: int) -> dict:
    """Изолирует DNS/сетевые операции; завершает дочерний процесс по тайм-ауту."""
    ctx = mp.get_context("spawn")
    receiver, sender = ctx.Pipe(duplex=False)
    worker = ctx.Process(target=_certificate_worker, args=(sender, name, timeout))
    started = False
    deadline = time.monotonic() + timeout
    try:
        worker.start()
        started = True
        sender.close()
        if not receiver.poll(max(0.0, deadline - time.monotonic())):
            return failure("deadline", f"Проверка не завершилась за {timeout} с.")
        try:
            return receiver.recv()
        except (EOFError, OSError) as exc:
            return failure("worker", exc)
    except (OSError, RuntimeError) as exc:
        return failure("worker", exc)
    finally:
        sender.close()
        receiver.close()
        if started:
            worker.join(0.2)
            if worker.is_alive():
                worker.terminate()
                worker.join(0.5)
            if worker.is_alive():
                worker.kill()
                worker.join()
            worker.close()


def check_http(name: str, timeout: int) -> dict:
    """Опциональная HEAD-проверка того же домена по обычному DNS и HTTPS."""
    curl = shutil.which("curl")
    if not curl:
        return {"status": "error", "error_type": "curl_missing", "error": "curl не найден."}

    argv = [
        curl, "--disable", "--silent", "--show-error", "--head",
        "--noproxy", "*", "--proto", "=https", "--tlsv1.2", "--connect-timeout", str(timeout),
        "--max-time", str(timeout), "--output", os.devnull,
        "--write-out", "%{http_version}\t%{http_code}\n", f"https://{name}/",
    ]
    environment = os.environ.copy()
    environment.pop("SSLKEYLOGFILE", None)
    try:
        result = subprocess.run(
            argv, shell=False, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=timeout + 1, check=False, env=environment,
        )
    except subprocess.TimeoutExpired:
        return {"status": "error", "error_type": "deadline", "error": "Истёк тайм-аут HTTP."}
    except OSError as exc:
        return {"status": "error", "error_type": "curl_start", "error": str(exc)[:500]}

    if result.returncode != 0:
        return {
            "status": "error", "error_type": "curl", "returncode": result.returncode,
            "error": (result.stderr.strip() or "HTTP-запрос не выполнен.")[:500],
        }
    fields = result.stdout.strip().split("\t")
    if len(fields) != 2 or not re.fullmatch(r"[1-9]\d?(?:\.\d+)?", fields[0]):
        return {"status": "error", "error_type": "curl_output", "error": "Нет версии HTTP в ответе."}
    if not re.fullmatch(r"[1-5]\d{2}", fields[1]):
        return {"status": "error", "error_type": "curl_output", "error": "Нет HTTP-статуса в ответе."}
    return {
        "status": "ok",
        "method": "HEAD",
        "http_version": fields[0],        # Реально использованная версия, не предположение.
        "http_status": int(fields[1]),    # HTTP-статус не равнозначен ошибке TLS.
    }


def save_report(path: Path, content: str) -> None:
    """Создаёт новый файл; существующий файл или симлинк не перезаписывается."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(content)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
                                     allow_abbrev=False)
    parser.add_argument("domain", type=hostname, help="Один домен, который вы вправе проверять.")
    parser.add_argument("--authorized", action="store_true", help="Подтверждаю право на проверку.")
    parser.add_argument("--http", action="store_true", help="Дополнительно выполнить один HTTPS HEAD через curl.")
    parser.add_argument("--timeout", type=timeout_value, default=DEFAULT_TIMEOUT,
                        help="Тайм-аут каждого этапа, 2–30 с (по умолчанию 8).")
    parser.add_argument("--output", type=Path, help="Путь к новому JSON-файлу; без перезаписи.")
    args = parser.parse_args(argv)
    if not args.authorized:
        parser.error("Укажите --authorized только для домена, который вправе проверять.")
    if args.output is not None and os.path.lexists(args.output):
        parser.error("Файл отчёта уже существует; выберите новое имя.")

    if hasattr(os, "geteuid") and os.geteuid() == 0:
        print("Предупреждение: для проверки не требуются права root.", file=sys.stderr)

    checked_at = iso_time(utc_now())
    cert = certificate_with_deadline(args.domain, args.timeout)
    http = {"status": "not_requested"}
    if args.http:
        if cert.get("certificate_verified") is True and cert["status"] != "error":
            http = check_http(args.domain, args.timeout)
        else:
            http = {"status": "skipped", "reason": "certificate_check_failed"}

    ok = cert["status"] in ("ok", "warning") and (not args.http or http["status"] == "ok")
    report = {
        "schema_version": 1,
        "checked_at_utc": checked_at,
        "domain": args.domain,
        "port": PORT,
        "ok": ok,
        "certificate": cert,
        "http": http,
    }
    data = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    print(data, end="")
    if args.output is not None:
        try:
            save_report(args.output, data)
        except OSError as exc:
            print(f"Не удалось сохранить отчёт: {exc}", file=sys.stderr)
            return 3
    return 0 if ok else 1


if __name__ == "__main__":
    mp.freeze_support()
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nПроверка отменена.", file=sys.stderr)
        sys.exit(130)
