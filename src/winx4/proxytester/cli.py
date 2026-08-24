from __future__ import annotations

import argparse
import asyncio
import datetime
import os
import sys

from .bytemeter import make_provider
from .ebpfmeter import DEFAULT_SCRIPT, ConnMeter
from .models import CheckResult
from .parser import parse_file, parse_lines
from .plugins import ENRICHERS, SINKS, TRANSPORTS

DEFAULT_ECHO = os.environ.get("WX4_ECHO", "https://ip.motn.online/")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="winx4-proxytest")
    ap.add_argument("proxies", nargs="?", help="proxy list file (default: stdin)")
    ap.add_argument("--echo", default=DEFAULT_ECHO, help="echo endpoint URL")
    ap.add_argument(
        "--echo2",
        help="optional second echo URL (e.g. http:// variant); captures the proxy's "
        "egress IP for both protocols",
    )
    ap.add_argument("--concurrency", type=int, default=1000, help="concurrent checks")
    ap.add_argument("--timeout", type=float, default=3.0, help="per-check timeout in seconds")
    ap.add_argument("--no-dedupe", action="store_true", help="do not dedupe identical proxies")
    ap.add_argument("--geo", help="GeoLite2-City.mmdb path")
    ap.add_argument("--asn", help="GeoLite2-ASN.mmdb path")
    ap.add_argument("--out", help="write results to CSV file")
    ap.add_argument("--out-json", help="write results to JSONL file")
    ap.add_argument("--alive-only", action="store_true", help="only output working proxies")
    ap.add_argument("--dead-only", action="store_true", help="only output dead proxies")
    ap.add_argument(
        "--country",
        help="only output proxies from this country ISO code (requires --geo)",
    )
    ap.add_argument(
        "--bytes-service",
        help="systemd service name to meter exact network bytes via IP accounting "
        "(e.g. winx4-ui when running under systemd)",
    )
    ap.add_argument(
        "--ebpf",
        action="store_true",
        help="attach the eBPF observer and attribute exact per-connection bytes "
        "to each check (Linux/root only; script path via WX4_EBPF_SCRIPT)",
    )
    ap.add_argument("--quiet", action="store_true", help="no progress or summary")
    args = ap.parse_args(argv)

    if args.country and not args.geo:
        ap.error("--country requires --geo")

    sink = None
    sink_fh = None
    if args.out:
        sink_fh = open(args.out, "w", newline="", encoding="utf-8")
        sink = SINKS["csv"](sink_fh)
    elif args.out_json:
        sink_fh = open(args.out_json, "w", encoding="utf-8")
        sink = SINKS["jsonl"](sink_fh)
    else:
        sink = SINKS["plain"]()

    def keep(result: CheckResult) -> bool:
        if args.alive_only and result.status != "ok":
            return False
        if args.dead_only and result.status == "ok":
            return False
        if (
            not args.out
            and not args.out_json
            and not args.alive_only
            and not args.dead_only
            and result.status != "ok"
        ):
            return False
        if args.country:
            if not result.geo or result.geo.country_iso != args.country.upper():
                return False
        return True

    def on_result(result: CheckResult, stats) -> None:
        if keep(result):
            sink.write(result)
        if not args.quiet and stats.done % 500 == 0:
            print(
                f"  {stats.done}/{stats.total}  alive={stats.alive}  "
                f"{stats.checks_per_sec:.0f} checks/s",
                file=sys.stderr,
                flush=True,
            )

    entries = (
        parse_file(args.proxies)
        if args.proxies and args.proxies != "-"
        else parse_lines(sys.stdin)
    )
    enricher = (
        ENRICHERS["geolite2"](args.geo, args.asn) if (args.geo or args.asn) else None
    )
    conn_meter = (
        ConnMeter(os.environ.get("WX4_EBPF_SCRIPT", DEFAULT_SCRIPT), os.getpid())
        if args.ebpf
        else None
    )
    try:
        stats = asyncio.run(
            TRANSPORTS["local"](
                entries,
                args.echo,
                args.concurrency,
                timeout=datetime.timedelta(seconds=args.timeout),
                on_result=on_result,
                dedupe=not args.no_dedupe,
                enricher=enricher,
                echo2_url=args.echo2,
                byte_provider=make_provider(args.bytes_service),
                conn_meter=conn_meter,
            )
        )
    finally:
        sink.close()
        if enricher:
            enricher.close()
        if sink_fh:
            sink_fh.close()

    if not args.quiet:
        print(
            f"checked: {stats.done}  alive: {stats.alive}  dead: {stats.done - stats.alive}  "
            f"wall: {stats.wall_s:.1f}s  throughput: {stats.checks_per_sec:.0f} checks/s",
            file=sys.stderr,
        )
        print(f"avg latency: {stats.avg_latency_ms:.1f} ms", file=sys.stderr)
        if stats.bytes_in is not None and stats.bytes_out is not None:
            print(
                f"bytes: in={stats.bytes_in:,} out={stats.bytes_out:,} "
                f"({(stats.bytes_in + stats.bytes_out) / 1048576:.2f} MiB total)",
                file=sys.stderr,
            )
        if stats.reasons:
            print(
                "reasons: " + ", ".join(f"{k}={v}" for k, v in stats.reasons.most_common()),
                file=sys.stderr,
            )
    return 0


if __name__ == "__main__":
    sys.exit(main())
