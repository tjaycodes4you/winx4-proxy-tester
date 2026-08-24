from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True, frozen=True)
class ProxyEntry:
    line: str
    scheme: str
    host: str
    port: int
    username: str | None = None
    password: str | None = None

    @property
    def key(self) -> tuple[str, str, int, str | None]:
        return (self.scheme, self.host, self.port, self.username)


@dataclass(slots=True)
class GeoInfo:
    country: str | None = None
    country_iso: str | None = None
    city: str | None = None
    region: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    timezone: str | None = None
    asn: int | None = None
    org: str | None = None


@dataclass(slots=True)
class CheckResult:
    proxy: ProxyEntry
    status: str
    reason: str | None = None
    total_ms: float | None = None
    egress_ip: str | None = None
    egress_ip2: str | None = None
    anonymity: str | None = None
    http_version: str | None = None
    echo_headers: dict[str, str] | None = None
    geo: GeoInfo | None = None
    bytes_in: int | None = None
    bytes_out: int | None = None
    conn_ms: float | None = None
    local_ports: tuple[int, ...] = ()
    start_mono: int | None = None
