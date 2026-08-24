from __future__ import annotations

import asyncio
import datetime
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Callable, Iterable

from .enricher import GeoEnricher
from .models import CheckResult, GeoInfo, ProxyEntry
from .pipeline import RunStats
from .plugins import TRANSPORTS

DC_KEYWORDS = (
    "amazon", "aws", "microsoft", "azure", "google", "gcp", "ovh", "digitalocean",
    "contabo", "hetzner", "m247", "datacamp", "leaseweb", "vultr", "hosting",
    "data center", "datacenter", "choopa", "psychz", "multacom", "pccwg",
    "softlayer", "ibm", "oracle", "tencent", "alibaba", "huawei", "linode",
    "akamai", "cloudflare", "fastly", "aiven", "oneprovider", "colocrossing",
    "interserver", "dedicated", "colo", "server", "vpn", "proxy", "the constant",
)


def classify_geo(geo: GeoInfo) -> str:
    org = (geo.org or "").lower()
    if not org:
        return "unknown"
    return "dc" if any(k in org for k in DC_KEYWORDS) else "resi"


@dataclass
class RotationRound:
    index: int
    results: list[CheckResult]
    stats: RunStats


@dataclass
class RotationStudy:
    entries: list[ProxyEntry]
    interval_s: float
    rounds: list[RotationRound] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    cancelled: bool = False

    def per_session(self) -> dict[str, list[str | None]]:
        hist: dict[str, list[str | None]] = {
            e.line: [None] * len(self.rounds) for e in self.entries
        }
        for i, r in enumerate(self.rounds):
            for res in r.results:
                hist[res.proxy.line][i] = res.egress_ip
        return hist

    def rotation_events(self) -> list[tuple[str, int, str, str]]:
        events: list[tuple[str, int, str, str]] = []
        for line, ips in self.per_session().items():
            for i in range(1, len(ips)):
                a, b = ips[i - 1], ips[i]
                if a and b and a != b:
                    events.append((line, i, a, b))
        return events

    def hold_distribution(self) -> Counter:
        dist: Counter = Counter()
        for ips in self.per_session().values():
            run_len = 0
            prev = None
            for ip in ips:
                if ip and ip == prev:
                    run_len += 1
                else:
                    if prev and run_len > 0:
                        dist[run_len] += 1
                    prev, run_len = (ip, 1) if ip else (None, 0)
            if prev and run_len > 0:
                dist[run_len] += 1
        return dist

    def pool_sizes(self) -> dict[str, int]:
        return {
            line: len({ip for ip in ips if ip})
            for line, ips in self.per_session().items()
        }

    def shared_ips(self) -> dict[str, list[str]]:
        by_ip: dict[str, set[str]] = defaultdict(set)
        for line, ips in self.per_session().items():
            for ip in ips:
                if ip:
                    by_ip[ip].add(line)
        return {ip: sorted(s) for ip, s in by_ip.items() if len(s) > 1}

    def flips_per_round(self) -> dict[int, int]:
        counts = Counter(i for _, i, _, _ in self.rotation_events())
        return {i: counts.get(i, 0) for i in range(1, len(self.rounds))}

    def protocol_anomalies(self) -> list[tuple[str, int, str, str]]:
        anomalies: list[tuple[str, int, str, str]] = []
        for i, r in enumerate(self.rounds):
            for res in r.results:
                if res.egress_ip and res.egress_ip2 and res.egress_ip != res.egress_ip2:
                    anomalies.append((res.proxy.line, i, res.egress_ip, res.egress_ip2))
        return anomalies

    def quality_breakdown(self) -> Counter:
        quality: Counter = Counter()
        for r in self.rounds:
            for res in r.results:
                if res.egress_ip and res.geo:
                    quality[classify_geo(res.geo)] += 1
        return quality

    def alive_per_round(self) -> list[int]:
        return [r.stats.alive for r in self.rounds]

    def total_wall_s(self) -> float:
        return time.time() - self.started_at if self.rounds else 0.0


async def rotation_study(
    entries: Iterable[ProxyEntry],
    echo_url: str,
    concurrency: int,
    timeout: datetime.timedelta,
    rounds: int,
    interval_s: float,
    echo2_url: str | None = None,
    enricher: GeoEnricher | None = None,
    byte_provider: Callable[[], tuple[int, int] | None] | None = None,
    cancel: asyncio.Event | None = None,
    on_round: Callable[[RotationRound, RotationStudy], None] | None = None,
) -> RotationStudy:
    entry_list = list(entries)
    study = RotationStudy(entries=entry_list, interval_s=interval_s)
    for i in range(rounds):
        if cancel is not None and cancel.is_set():
            study.cancelled = True
            break
        results: list[CheckResult] = []
        stats = await TRANSPORTS["local"](
            entry_list,
            echo_url,
            concurrency,
            timeout=timeout,
            on_result=lambda r, s: results.append(r),
            dedupe=True,
            enricher=enricher,
            echo2_url=echo2_url,
            byte_provider=byte_provider,
            cancel=cancel,
        )
        study.rounds.append(RotationRound(index=i, results=results, stats=stats))
        if on_round is not None:
            on_round(study.rounds[-1], study)
        if i < rounds - 1 and interval_s > 0:
            waited = 0.0
            while waited < interval_s:
                if cancel is not None and cancel.is_set():
                    study.cancelled = True
                    break
                step = min(0.5, interval_s - waited)
                await asyncio.sleep(step)
                waited += step
            if study.cancelled:
                break
    return study
