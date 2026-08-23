from __future__ import annotations

import datetime
import ipaddress
import os
import time

import wreq
from wreq.exceptions import (
    BuilderError,
    ConnectionError,
    ConnectionResetError,
    ProxyConnectionError,
    TimeoutError,
    TlsError,
)

from .plugins import checker as register_checker

from .models import CheckResult, ProxyEntry

CHECK_TIMEOUT = datetime.timedelta(
    seconds=float(os.environ.get("WX4_CHECK_TIMEOUT", "3"))
)

LEAK_HEADERS = {
    "via",
    "forwarded",
    "x-forwarded-for",
    "x-real-ip",
    "true-client-ip",
    "client-ip",
    "x-client-ip",
    "x-http-proxy",
    "proxy-connection",
    "x-proxy-id",
    "x-originating-ip",
}


def classify_anonymity(
    headers: dict[str, str], baseline: dict[str, str] | None
) -> str:
    leak = {k: v for k, v in headers.items() if k in LEAK_HEADERS}
    if not leak:
        return "elite"
    if baseline is None:
        return "unknown"
    base_ip = (baseline.get("cf-connecting-ip") or "").strip()
    if base_ip and base_ip in " ".join(leak.values()):
        return "transparent"
    return "anonymous"


def _proxy_object(entry: ProxyEntry):
    host = f"[{entry.host}]" if ":" in entry.host else entry.host
    url = f"{entry.scheme}://{host}:{entry.port}"
    if entry.username is not None:
        return wreq.Proxy.all(url, username=entry.username, password=entry.password or "")
    return wreq.Proxy.all(url)


def _classify_error(exc: Exception) -> str:
    if isinstance(exc, TimeoutError):
        return "timeout"
    if isinstance(exc, (ProxyConnectionError, ConnectionError, ConnectionResetError)):
        return "connect"
    if isinstance(exc, TlsError):
        return "tls"
    if isinstance(exc, BuilderError):
        return "bad_proxy"
    name = type(exc).__name__.lower()
    if "dns" in name or "resolve" in name:
        return "dns"
    if "auth" in name or "proxy" in name:
        return "proxy"
    return "error"


async def fetch_baseline(
    echo_url: str, timeout: datetime.timedelta = CHECK_TIMEOUT
) -> dict[str, str]:
    client = wreq.Client()
    try:
        resp = await client.get(echo_url, timeout=timeout)
        data = await resp.json()
        return {k.lower(): v for k, v in data.get("headers", {}).items()}
    except Exception:
        return {}
    finally:
        client.close()


async def _parse_echo(resp) -> tuple[str | None, dict[str, str] | None]:
    try:
        data = await resp.json()
    except Exception:
        data = None
    if isinstance(data, dict) and isinstance(data.get("headers"), dict) and "ip" in data:
        headers = {k.lower(): v for k, v in data.get("headers", {}).items()}
        return data.get("ip"), headers
    text = (await resp.text()).strip()
    try:
        return str(ipaddress.ip_address(text)), None
    except ValueError:
        return None, None


@register_checker("echo")
async def check_one(
    client: wreq.Client,
    entry: ProxyEntry,
    echo_url: str,
    baseline: dict[str, str] | None,
    timeout: datetime.timedelta = CHECK_TIMEOUT,
    echo2_url: str | None = None,
) -> CheckResult:
    start = time.perf_counter()
    try:
        resp = await client.get(echo_url, proxy=_proxy_object(entry), timeout=timeout)
        total_ms = (time.perf_counter() - start) * 1000
        code = resp.status.as_int()
        if code == 407:
            return CheckResult(entry, "error", reason="auth", total_ms=total_ms)
        if code != 200:
            return CheckResult(entry, "error", reason=f"http{code}", total_ms=total_ms)
        egress, headers = await _parse_echo(resp)
        if egress is None:
            return CheckResult(entry, "error", reason="bad_echo", total_ms=total_ms)
        egress2 = None
        if echo2_url:
            try:
                resp2 = await client.get(
                    echo2_url, proxy=_proxy_object(entry), timeout=timeout
                )
                if resp2.status.as_int() == 200:
                    egress2, _ = await _parse_echo(resp2)
            except Exception:
                pass
        return CheckResult(
            entry,
            "ok",
            total_ms=total_ms,
            egress_ip=egress,
            egress_ip2=egress2,
            anonymity=classify_anonymity(headers, baseline) if headers else None,
            http_version=str(resp.version).rsplit(".", 1)[-1],
            echo_headers=headers,
        )
    except Exception as exc:
        return CheckResult(
            entry,
            "error",
            reason=_classify_error(exc),
            total_ms=(time.perf_counter() - start) * 1000,
        )
