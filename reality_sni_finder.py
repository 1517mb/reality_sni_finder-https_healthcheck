#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Reality SNI Finder (improved)
- Scans ref /24 plus ±N neighbor /24 blocks in a single masscan run (tcp/443).
- Probes TLS (no SNI), extracts DER cert locally via OpenSSL (no 2nd network call).
- Filters for TLS 1.3, expands wildcard SANs, caps domains per IP.
- Strictly verifies TLS 1.3 + HTTP/2 + trusted certificate chain via curl --resolve.
- Scores by real TLS handshake latency (time_appconnect) and normalized subnet distance.
- Outputs top N unique domains to domains.txt (or custom file).

Env overrides (compatible with legacy variables):
  RSF_BLOCKS (default 6), RSF_RATE (4000), RSF_TIMEOUT (8), RSF_THREADS (64),
  RSF_INCLUDE_GENERIC (0/1), RSF_VERIFY_H2 (1/0), RSF_REF_IP (IPv4),
  RSF_MAX_PER_IP (8), RSF_TOPN (30), RSF_WAIT (2).
"""

import argparse
import concurrent.futures
import ipaddress
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.request
from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Set, Tuple

# Домены крупных CDN/прокси, которые часто нежелательны для Reality
GENERIC_DOMAINS = frozenset({
    "cloudflaressl.com",
    "cloudflare.com",
    "akamai.net",
    "akamaiedge.net",
    "cloudfront.net",
    "edgekey.net",
    "edgesuite.net",
    "fastly.net",
})

BLOCKED_TLDS = (".local", ".lan", ".internal", ".home", ".arpa", ".invalid")

DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$"
)
CN_RE = re.compile(r"Subject:.*?\bCN\s*=\s*([^,\n/]+)")
SAN_RE = re.compile(r"DNS:([^,\s]+)")


@dataclass
class ProbeResult:
    ip: str
    ok: bool = False
    latency_ms: Optional[float] = None
    alpn: Optional[str] = None
    has_tls13: bool = False
    cert_cn: Optional[str] = None
    cert_sans: List[str] = field(default_factory=list)


class Progress:
    """Потокобезопасный прогресс-бар с троттлингом перерисовки."""

    def __init__(self, total: int, title: str, width: int = 40):
        self.total = max(1, total)
        self.title = title
        self.width = width
        self.done = 0
        self.lock = threading.Lock()
        self.start = time.monotonic()
        self.last_draw = 0.0
        self.is_tty = sys.stdout.isatty()
        self._render(force=True)

    def advance(self, n: int = 1) -> None:
        with self.lock:
            self.done = min(self.total, self.done + n)
            now = time.monotonic()
            if now - self.last_draw >= 0.05 or self.done == self.total:
                self._render()
                self.last_draw = now

    def finish(self) -> None:
        with self.lock:
            self.done = self.total
            self._render(end=True, force=True)

    def _render(self, end: bool = False, force: bool = False) -> None:
        if not self.is_tty and not end:
            return
        ratio = self.done / self.total
        filled = int(self.width * ratio)
        bar = "█" * filled + "░" * (self.width - filled)
        pct = f"{int(ratio * 100):3d}%"
        elapsed = time.monotonic() - self.start
        prefix = "\r" if self.is_tty else ""
        msg = f"{prefix}{self.title:<18} [{bar}] {pct} ({self.done}/{self.total}, {elapsed:0.1f}s)"
        sys.stdout.write(msg)
        if end:
            sys.stdout.write("\n")
        sys.stdout.flush()


def die(msg: str, code: int = 1) -> None:
    sys.stderr.write(f"[!] {msg}\n")
    sys.exit(code)


def check_tool(tool: str) -> None:
    if shutil.which(tool) is None:
        die(f"Required tool not found in PATH: {tool}")


def public_ipv4_autodetect(timeout: float = 4.0) -> Optional[str]:
    """Определяет внешний IPv4 через встроенный urllib без запуска bash."""
    endpoints = (
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://ipv4.icanhazip.com",
    )
    for url in endpoints:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "RealitySNIFinder/2.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                candidate = resp.read().decode("ascii", errors="ignore").strip()
            addr = ipaddress.ip_address(candidate)
            if addr.version == 4:
                return str(addr)
        except Exception:
            continue
    return None


def neighbor_24_cidrs(ref_ip: str, blocks_each_side: int) -> List[str]:
    addr = ipaddress.ip_address(ref_ip)
    if addr.version != 4:
        die("Only IPv4 is supported.")
    ref_net = ipaddress.ip_network(f"{ref_ip}/24", strict=False)
    ref_base = int(ref_net.network_address)

    cidrs: List[str] = []
    seen: Set[str] = set()
    for offset in range(-blocks_each_side, blocks_each_side + 1):
        net_int = ref_base + offset * 256
        if 0 <= net_int <= 0xFFFFFFFF:
            cidr = str(ipaddress.ip_network(f"{ipaddress.IPv4Address(net_int)}/24", strict=True))
            if cidr not in seen:
                seen.add(cidr)
                cidrs.append(cidr)
    return cidrs


def run_masscan(cidrs: Sequence[str], rate: int, wait: int = 2) -> List[str]:
    """Сканирует все /24 подсети за один запуск masscan."""
    cmd = [
        "masscan",
        ",".join(cidrs),
        "-p443",
        "--rate", str(rate),
        "--wait", str(wait),
        "--open-only",
        "-oL", "-",
    ]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if proc.returncode != 0:
        err_lines = [line.strip() for line in proc.stderr.splitlines() if line.strip()]
        detail = err_lines[-1] if err_lines else f"exit code {proc.returncode}"
        die(f"masscan failed: {detail} (check sudo / CAP_NET_RAW)")

    ips: Set[str] = set()
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[0] == "open" and parts[1] == "tcp":
            ips.add(parts[3])
    return sorted(ips)


def parse_der_cert_with_openssl(der_bytes: bytes) -> Tuple[Optional[str], List[str]]:
    """Локально разбирает уже полученный DER-сертификат без повторного сетевого запроса."""
    try:
        proc = subprocess.run(
            ["openssl", "x509", "-inform", "DER", "-noout", "-text"],
            input=der_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=3.0,
        )
        if proc.returncode != 0:
            return None, []
        text = proc.stdout.decode("utf-8", errors="ignore")
    except Exception:
        return None, []

    cn_match = CN_RE.search(text)
    cn = cn_match.group(1).strip() if cn_match else None
    sans = SAN_RE.findall(text)
    return cn, sans


def create_probe_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    except Exception:
        pass
    try:
        ctx.set_alpn_protocols(["h2", "http/1.1"])
    except Exception:
        pass
    return ctx


def probe_tls_no_sni(ip: str, ctx: ssl.SSLContext, timeout: float = 3.0) -> ProbeResult:
    res = ProbeResult(ip=ip)
    t0 = time.monotonic()
    der_cert: Optional[bytes] = None

    try:
        with socket.create_connection((ip, 443), timeout=timeout) as sock:
            sock.settimeout(timeout)
            with ctx.wrap_socket(sock, server_hostname=None) as ssock:
                res.latency_ms = round((time.monotonic() - t0) * 1000.0, 2)
                res.ok = True
                res.has_tls13 = ssock.version() == "TLSv1.3"
                try:
                    res.alpn = ssock.selected_alpn_protocol()
                except Exception:
                    res.alpn = None
                der_cert = ssock.getpeercert(binary_form=True)
    except Exception:
        return res

    if der_cert:
        res.cert_cn, res.cert_sans = parse_der_cert_with_openssl(der_cert)
    return res


def is_valid_domain(domain: str) -> bool:
    d = domain.strip().lower().rstrip(".")
    if not d or len(d) >= 253 or d.endswith(BLOCKED_TLDS):
        return False
    return bool(DOMAIN_RE.match(d))


def is_generic_domain(domain: str) -> bool:
    return any(domain == g or domain.endswith("." + g) for g in GENERIC_DOMAINS)


def expand_wildcard(raw: str) -> List[str]:
    d = raw.strip().lower().rstrip(".")
    if d.startswith("*."):
        root = d[2:]
        if is_valid_domain(root):
            return [root, f"www.{root}"]
        return []
    return [d] if is_valid_domain(d) else []


def extract_domains(
    cn: Optional[str],
    sans: Sequence[str],
    include_generic: bool = True,
    max_domains: int = 8,
) -> List[str]:
    raw_items: List[str] = []
    if cn:
        raw_items.append(cn)
    raw_items.extend(sans)

    seen: Set[str] = set()
    result: List[str] = []
    for raw in raw_items:
        for dom in expand_wildcard(raw):
            if not include_generic and is_generic_domain(dom):
                continue
            if dom not in seen:
                seen.add(dom)
                result.append(dom)
                if len(result) >= max_domains:
                    return result
    return result


def verify_reality_target(
    domain: str,
    ip: str,
    timeout: float = 8.0,
    require_tls13: bool = True,
) -> Tuple[bool, Optional[float]]:
    """
    Строго проверяет:
    1) Успешный TLS 1.3 handshake с реальным SNI;
    2) Валидную цепочку сертификатов (ssl_verify_result == 0);
    3) Реально согласованный HTTP/2 (http_version == 2).
    """
    cmd = [
        "curl", "-sS", "-I",
        "--max-time", f"{timeout:.1f}",
        "--connect-timeout", f"{min(timeout, 5.0):.1f}",
        "--http2",
        "-o", os.devnull,
        "-w", "%{http_version} %{ssl_verify_result} %{time_appconnect}",
        "--resolve", f"{domain}:443:{ip}",
        f"https://{domain}/",
    ]
    if require_tls13:
        cmd.insert(3, "--tlsv1.3")

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=timeout + 2.0,
        )
        if proc.returncode != 0:
            return False, None
        parts = proc.stdout.strip().split()
        if len(parts) < 3:
            return False, None

        http_ver, ssl_verify, appconnect_raw = parts[0], parts[1], parts[2]
        if ssl_verify != "0" or not http_ver.startswith("2"):
            return False, None

        appconnect_sec = float(appconnect_raw.replace(",", "."))
        lat_ms = round(appconnect_sec * 1000.0, 2) if appconnect_sec > 0 else None
        return True, lat_ms
    except Exception:
        return False, None


def normalized_ip_distance(ip: str, ref_ip: str, blocks: int) -> float:
    """Возвращает расстояние в диапазоне [0.0, 1.0] относительно радиуса сканирования."""
    try:
        dist = abs(int(ipaddress.ip_address(ip)) - int(ipaddress.ip_address(ref_ip)))
        max_dist = max(1, blocks * 256 + 255)
        return min(dist / max_dist, 1.0)
    except Exception:
        return 1.0


def parse_args() -> argparse.Namespace:
    env = os.environ
    parser = argparse.ArgumentParser(description="Find optimal TLS 1.3 / HTTP/2 SNI domains near an IPv4 address.")
    parser.add_argument("--ref-ip", default=env.get("RSF_REF_IP", "").strip(), help="Reference IPv4 (autodetected if omitted)")
    parser.add_argument("--blocks", type=int, default=int(env.get("RSF_BLOCKS", "6")), help="Neighbor /24 blocks on each side")
    parser.add_argument("--rate", type=int, default=int(env.get("RSF_RATE", "4000")), help="masscan packet rate")
    parser.add_argument("--wait", type=int, default=int(env.get("RSF_WAIT", "2")), help="masscan cooldown wait seconds")
    parser.add_argument("--timeout", type=float, default=float(env.get("RSF_TIMEOUT", "8")), help="Network timeout in seconds")
    parser.add_argument("--threads", type=int, default=int(env.get("RSF_THREADS", "64")), help="Worker thread count")
    parser.add_argument("--max-per-ip", type=int, default=int(env.get("RSF_MAX_PER_IP", "8")), help="Max SAN domains checked per IP")
    parser.add_argument("--top", type=int, default=int(env.get("RSF_TOPN", "30")), help="Number of domains to save")
    parser.add_argument("--output", default="domains.txt", help="Output filename")
    parser.add_argument(
        "--include-generic",
        action=argparse.BooleanOptionalAction,
        default=env.get("RSF_INCLUDE_GENERIC", "1") == "1",
        help="Include shared CDN domains (Cloudflare, Akamai, etc.)",
    )
    parser.add_argument(
        "--verify-h2",
        action=argparse.BooleanOptionalAction,
        default=env.get("RSF_VERIFY_H2", "1") == "1",
        help="Strictly verify TLS 1.3 + HTTP/2 + valid cert via curl",
    )
    parser.add_argument(
        "--require-tls13",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Require TLS 1.3 support (essential for REALITY)",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Print top results with latency and IP")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    for tool in ("masscan", "curl", "openssl"):
        check_tool(tool)

    ref_ip = args.ref_ip or public_ipv4_autodetect()
    if not ref_ip:
        die("Cannot detect public IPv4 automatically. Pass --ref-ip or set RSF_REF_IP.")

    cidrs = neighbor_24_cidrs(ref_ip, args.blocks)

    # 1. Scan all blocks in one masscan run
    sys.stdout.write(f"Scanning {len(cidrs)} /24 blocks around {ref_ip}...\n")
    sys.stdout.flush()
    ips = [ip for ip in run_masscan(cidrs, args.rate, wait=args.wait) if ip != ref_ip]
    if not ips:
        die("No neighbor hosts with port 443 were found.")

    # 2. TLS probe (no SNI) + local DER cert parsing
    ssl_ctx = create_probe_ssl_context()
    probe_timeout = max(2.5, args.timeout - 2.0)
    pb_probe = Progress(len(ips), "TLS probing")

    def _probe(ip: str) -> ProbeResult:
        res = probe_tls_no_sni(ip, ssl_ctx, timeout=probe_timeout)
        pb_probe.advance()
        return res

    probes: List[ProbeResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        for res in ex.map(_probe, ips):
            if res.ok and (not args.require_tls13 or res.has_tls13):
                probes.append(res)
    pb_probe.finish()

    if not probes:
        die("No suitable TLS hosts responded (try --no-require-tls13 if not using REALITY).")

    # 3. Extract and deduplicate (ip, domain) candidates
    candidates: List[Tuple[str, Optional[float], str]] = []
    seen_pairs: Set[Tuple[str, str]] = set()
    for p in probes:
        domains = extract_domains(
            p.cert_cn,
            p.cert_sans,
            include_generic=args.include_generic,
            max_domains=args.max_per_ip,
        )
        for dom in domains:
            if (p.ip, dom) not in seen_pairs:
                seen_pairs.add((p.ip, dom))
                candidates.append((p.ip, p.latency_ms, dom))

    if not candidates:
        die("No valid domains extracted from certificates.")

    # 4. Strict HTTP/2 + TLS 1.3 + Cert verification
    if args.verify_h2:
        pb_verify = Progress(len(candidates), "Verifying H2/TLS1.3")

        def _verify(item: Tuple[str, Optional[float], str]) -> Tuple[str, Optional[float], str, bool]:
            ip, probe_lat, dom = item
            ok, curl_lat = verify_reality_target(
                dom, ip, timeout=args.timeout, require_tls13=args.require_tls13
            )
            pb_verify.advance()
            return ip, (curl_lat if curl_lat is not None else probe_lat), dom, ok

        verified: List[Tuple[str, Optional[float], str]] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
            for ip, lat, dom, ok in ex.map(_verify, candidates):
                if ok:
                    verified.append((ip, lat, dom))
        pb_verify.finish()
        candidates = verified

        if not candidates:
            die("No domains passed strict TLS 1.3 + HTTP/2 + valid cert verification.")

    # 5. Score: real TLS latency (ms) + up to 25 ms penalty for IP distance
    scored: List[Tuple[float, float, str, str]] = []
    for ip, lat, dom in candidates:
        eff_lat = lat if lat is not None else 5000.0
        dist_penalty = 25.0 * normalized_ip_distance(ip, ref_ip, args.blocks)
        scored.append((eff_lat + dist_penalty, eff_lat, dom, ip))
    scored.sort(key=lambda x: x[0])

    # 6. Deduplicate domains while preserving best score
    top_entries: List[Tuple[float, str, str]] = []
    seen_doms: Set[str] = set()
    for _, eff_lat, dom, ip in scored:
        if dom not in seen_doms:
            seen_doms.add(dom)
            top_entries.append((eff_lat, dom, ip))
            if len(top_entries) >= args.top:
                break

    with open(args.output, "w", encoding="utf-8") as f:
        f.write("\n".join(dom for _, dom, _ in top_entries) + "\n")

    print(f"[✓] Wrote {len(top_entries)} domains to {args.output}")
    if args.verbose:
        for lat, dom, ip in top_entries:
            print(f"    {lat:6.1f} ms  {ip:<15}  {dom}")


if __name__ == "__main__":
    main()