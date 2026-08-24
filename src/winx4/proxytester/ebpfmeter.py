from __future__ import annotations

import asyncio
import json
import os
import time

SLACK_NS = 2_500_000_000
PRUNE_AGE_NS = 60_000_000_000
DEFAULT_SCRIPT = "/root/winx4/ebpf/conn_bytes.py"


class ConnEvent:
    __slots__ = ("lport", "dport", "bytes_in", "bytes_out", "start", "dur_ms", "claimed")

    def __init__(self, lport, dport, bytes_in, bytes_out, start, dur_ms):
        self.lport = lport
        self.dport = dport
        self.bytes_in = bytes_in
        self.bytes_out = bytes_out
        self.start = start
        self.dur_ms = dur_ms
        self.claimed = False


class ConnMeter:
    def __init__(self, script: str, pid: int):
        self.script = script or DEFAULT_SCRIPT
        self.pid = pid
        self.events: list[ConnEvent] = []
        self.proc = None
        self._ready = asyncio.Event()
        self._reader = None

    async def start(self) -> bool:
        if not os.path.exists(self.script):
            return False
        try:
            self.proc = await asyncio.create_subprocess_exec(
                "python3", "-u", self.script, "--pid", str(self.pid), "--json",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
        except OSError:
            return False
        self._attach_ready = asyncio.Event()
        self._reader = asyncio.create_task(self._read())
        try:
            await asyncio.wait_for(self._attach_ready.wait(), 15)
        except asyncio.TimeoutError:
            await self.stop()
            return False
        return True

    async def _read(self) -> None:
        async for line in self.proc.stdout:
            text = line.decode(errors="replace").strip()
            if text == "READY":
                self._attach_ready.set()
                continue
            try:
                d = json.loads(text)
            except (ValueError, TypeError):
                continue
            self.events.append(
                ConnEvent(
                    d["lport"], d["dport"], int(d["bytes_in"]), int(d["bytes_out"]),
                    int(d["start"]), float(d["dur_ms"]),
                )
            )
            self._prune()
            self._ready.set()

    async def claim(
        self,
        start_mono: int,
        dport: int,
        local_ports: tuple[int, ...],
        timeout: float = 0.3,
    ) -> tuple[int, int, float] | None:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while True:
            match = self._match(start_mono, dport, local_ports)
            if match is not None:
                return match
            remaining = deadline - loop.time()
            if remaining <= 0:
                return None
            self._ready.clear()
            try:
                await asyncio.wait_for(self._ready.wait(), remaining)
            except asyncio.TimeoutError:
                return None

    def _match(self, start_mono: int, dport: int, local_ports: tuple[int, ...]):
        if local_ports:
            matched = [e for e in self.events if not e.claimed and e.lport in local_ports]
            if matched:
                for e in matched:
                    e.claimed = True
                return (
                    sum(e.bytes_in for e in matched),
                    sum(e.bytes_out for e in matched),
                    max(e.dur_ms for e in matched),
                )
        best = None
        best_d = SLACK_NS
        for e in self.events:
            if e.claimed or e.dport != dport:
                continue
            d = abs(e.start - start_mono)
            if d < best_d:
                best_d = d
                best = e
        if best is not None:
            best.claimed = True
            return best.bytes_in, best.bytes_out, best.dur_ms
        return None

    def _prune(self) -> None:
        cutoff = time.monotonic_ns() - PRUNE_AGE_NS
        self.events = [e for e in self.events if e.start > cutoff]

    async def stop(self) -> None:
        if self._reader is not None:
            self._reader.cancel()
        if self.proc is not None:
            self.proc.terminate()
            try:
                await self.proc.wait()
            except (OSError, asyncio.TimeoutError):
                pass
