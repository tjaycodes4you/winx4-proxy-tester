from __future__ import annotations

import asyncio
import datetime
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Callable, Iterable

import wreq

from .checker import CHECK_TIMEOUT, check_one, fetch_baseline
from .enricher import GeoEnricher
from .models import CheckResult, ProxyEntry
from .plugins import CHECKERS, transport as register_transport


@dataclass
class RunStats:
    total: int = 0
    done: int = 0
    alive: int = 0
    reasons: Counter = field(default_factory=Counter)
    results: list[CheckResult] = field(default_factory=list)
    latency_ms: list[float] = field(default_factory=list)
    started: float = field(default_factory=time.perf_counter)

    @property
    def checks_per_sec(self) -> float:
        elapsed = time.perf_counter() - self.started
        return self.done / elapsed if elapsed > 0 else 0.0

    @property
    def wall_s(self) -> float:
        return time.perf_counter() - self.started

    @property
    def avg_latency_ms(self) -> float:
        return sum(self.latency_ms) / len(self.latency_ms) if self.latency_ms else 0.0


async def _check_cancellable(
    check_fn, client, entry, echo_url, baseline, timeout, cancel: asyncio.Event,
    echo2_url: str | None = None,
) -> CheckResult:
    check_task = asyncio.create_task(
        check_fn(
            client, entry, echo_url, baseline, timeout=timeout, echo2_url=echo2_url
        )
    )
    cancel_task = asyncio.create_task(cancel.wait())
    done, _ = await asyncio.wait(
        {check_task, cancel_task}, return_when=asyncio.FIRST_COMPLETED
    )
    if cancel_task in done:
        check_task.cancel()
        try:
            await check_task
        except (asyncio.CancelledError, Exception):
            pass
        return CheckResult(entry, "error", reason="cancelled")
    cancel_task.cancel()
    return check_task.result()


@register_transport("local")
async def run(
    entries: Iterable[ProxyEntry],
    echo_url: str,
    concurrency: int,
    on_result: Callable[[CheckResult, RunStats], None] | None = None,
    dedupe: bool = True,
    enricher: GeoEnricher | None = None,
    timeout: datetime.timedelta = CHECK_TIMEOUT,
    cancel: asyncio.Event | None = None,
    checker: str = "echo",
    echo2_url: str | None = None,
) -> RunStats:
    check_fn = CHECKERS.get(checker)
    if check_fn is None:
        raise ValueError(f"unknown checker: {checker} (registered: {sorted(CHECKERS)})")
    client = wreq.Client(pool_max_idle_per_host=0)
    baseline = await fetch_baseline(echo_url, timeout=timeout)
    stats = RunStats()
    queue: asyncio.Queue[ProxyEntry | None] = asyncio.Queue(maxsize=concurrency * 4)
    seen: set[tuple] = set()

    async def produce() -> None:
        for entry in entries:
            if cancel is not None and cancel.is_set():
                break
            if dedupe:
                if entry.key in seen:
                    continue
                seen.add(entry.key)
            stats.total += 1
            await queue.put(entry)
        await queue.put(None)

    def record(result: CheckResult) -> None:
        stats.done += 1
        stats.results.append(result)
        if result.status == "ok":
            stats.alive += 1
        else:
            stats.reasons[result.reason or "error"] += 1
        if result.total_ms is not None:
            stats.latency_ms.append(result.total_ms)
        if on_result is not None:
            on_result(result, stats)

    async def worker() -> None:
        while True:
            entry = await queue.get()
            if entry is None:
                await queue.put(None)
                return
            if cancel is not None and cancel.is_set():
                continue
            try:
                if cancel is not None:
                    result = await _check_cancellable(
                        check_fn, client, entry, echo_url, baseline, timeout, cancel,
                        echo2_url=echo2_url,
                    )
                else:
                    result = await check_fn(
                        client, entry, echo_url, baseline, timeout=timeout,
                        echo2_url=echo2_url,
                    )
            except Exception as exc:
                result = CheckResult(entry, "error", reason=type(exc).__name__)
            try:
                if enricher is not None and result.egress_ip:
                    result.geo = enricher.enrich(result.egress_ip)
            except Exception:
                pass
            record(result)

    try:
        producer = asyncio.create_task(produce())
        workers = [asyncio.create_task(worker()) for _ in range(concurrency)]
        await producer
        await asyncio.gather(*workers)
    finally:
        client.close()
    return stats
