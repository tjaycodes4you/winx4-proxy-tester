from __future__ import annotations

import argparse
import asyncio
import datetime
import json
import os
import re
import sys

from .bytemeter import make_provider
from .ebpfmeter import DEFAULT_SCRIPT, ConnMeter
from .models import CheckResult
from .parser import parse_file, parse_lines
from .plugins import ENRICHERS, SINKS, TRANSPORTS
from .rotation import RotationStudy, classify_geo, rotation_study
from .sinks import result_to_dict

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
    ap.add_argument(
        "--rotation",
        action="store_true",
        help="rotation study mode: repeat the check over N rounds at an interval "
        "to observe per-session egress IP rotation",
    )
    ap.add_argument("--rounds", type=int, default=20, help="rotation study rounds")
    ap.add_argument("--interval", type=float, default=60.0, help="seconds between rounds")
    ap.add_argument("--subset", type=int, help="only check the first N proxies")
    ap.add_argument("--quiet", action="store_true", help="no progress or summary")
    args = ap.parse_args(argv)

    if args.country and not args.geo:
        ap.error("--country requires --geo")

    entries = (
        parse_file(args.proxies)
        if args.proxies and args.proxies != "-"
        else parse_lines(sys.stdin)
    )
    if args.rotation:
        return _run_rotation(ap, args, entries)

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
        if stats.payload_in is not None:
            print(
                f"payload: in={stats.payload_in:,} out={stats.payload_out:,}  "
                f"overhead: in={stats.overhead_in:,} out={stats.overhead_out:,}",
                file=sys.stderr,
            )
        if stats.reasons:
            print(
                "reasons: " + ", ".join(f"{k}={v}" for k, v in stats.reasons.most_common()),
                file=sys.stderr,
            )
    return 0


def _rotation_out_paths(out_json: str | None) -> tuple[str | None, str | None]:
    if not out_json:
        return None, None
    stem, _, ext = out_json.rpartition(".")
    if re.search(r"\d+$", stem):
        return None, out_json
    stem = stem.rstrip("_")
    return f"{stem}{{i:02d}}.jsonl", f"{stem}_summary.json"


def _run_rotation(ap, args, entries) -> int:
    enricher = (
        ENRICHERS["geolite2"](args.geo, args.asn) if (args.geo or args.asn) else None
    )
    round_template, summary_path = _rotation_out_paths(args.out_json)
    entry_list = list(entries)
    if args.subset:
        entry_list = entry_list[: args.subset]

    def on_round(rnd, study: RotationStudy) -> None:
        if round_template:
            path = round_template.format(i=rnd.index + 1)
            with open(path, "w", encoding="utf-8") as fh:
                for res in rnd.results:
                    fh.write(json.dumps(result_to_dict(res)) + "\n")
        if not args.quiet:
            print(
                f"round {rnd.index + 1}/{len(entry_list) and args.rounds}: "
                f"alive={rnd.stats.alive}/{len(entry_list)}  "
                f"wall={study.total_wall_s():.0f}s",
                file=sys.stderr,
                flush=True,
            )

    try:
        study = asyncio.run(
            rotation_study(
                entry_list,
                args.echo,
                args.concurrency,
                timeout=datetime.timedelta(seconds=args.timeout),
                rounds=args.rounds,
                interval_s=args.interval,
                echo2_url=args.echo2,
                enricher=enricher,
                byte_provider=make_provider(args.bytes_service),
                on_round=on_round,
            )
        )
    finally:
        if enricher:
            enricher.close()

    _print_rotation_analysis(study, args)
    if summary_path:
        with open(summary_path, "w", encoding="utf-8") as fh:
            json.dump(_rotation_summary(study), fh, indent=2)
        print(f"summary: {summary_path}", file=sys.stderr)
    return 0


def _rotation_summary(study: RotationStudy) -> dict:
    return {
        "started_at": study.started_at,
        "interval_s": study.interval_s,
        "rounds": len(study.rounds),
        "cancelled": study.cancelled,
        "sessions": len(study.entries),
        "alive_per_round": study.alive_per_round(),
        "per_session": study.per_session(),
        "rotation_events": study.rotation_events(),
        "hold_distribution_rounds": dict(study.hold_distribution()),
        "pool_sizes": study.pool_sizes(),
        "shared_ips": study.shared_ips(),
        "flips_per_round": study.flips_per_round(),
        "protocol_anomalies": study.protocol_anomalies(),
        "quality": dict(study.quality_breakdown()),
    }


def _print_rotation_analysis(study: RotationStudy, args) -> None:
    if args.quiet:
        return
    rounds = len(study.rounds)
    if not rounds:
        print("rotation study: no rounds completed", file=sys.stderr)
        return
    per_session = study.per_session()
    events = study.rotation_events()
    sessions_with_rotations = len({line for line, *_ in events})
    pool_sizes = study.pool_sizes().values()
    shared = study.shared_ips()
    anomalies = study.protocol_anomalies()
    quality = study.quality_breakdown()
    print(
        f"rotation study: {rounds} rounds x {len(study.entries)} sessions "
        f"(interval {study.interval_s:.0f}s, wall {study.total_wall_s():.0f}s)",
        file=sys.stderr,
    )
    print(
        f"sessions with rotations: {sessions_with_rotations}/{len(study.entries)}  "
        f"total flips: {len(events)}",
        file=sys.stderr,
    )
    if events:
        flip_buckets = study.flips_per_round()
        max_flip_round = max(flip_buckets, key=flip_buckets.get)
        print(
            f"flips per round: "
            + ", ".join(f"r{i}={flip_buckets[i]}" for i in sorted(flip_buckets))
            + f"  (peak at round {max_flip_round} → likely global sync)",
            file=sys.stderr,
        )
    hold = study.hold_distribution()
    if hold:
        print(
            "hold distribution: "
            + ", ".join(
                f"{n} rounds (~{n * study.interval_s:.0f}s) x {c}"
                for n, c in sorted(hold.items())
            ),
            file=sys.stderr,
        )
    if pool_sizes:
        print(
            f"per-session pool size: min={min(pool_sizes)} max={max(pool_sizes)} "
            f"avg={sum(pool_sizes) / len(pool_sizes):.1f}",
            file=sys.stderr,
        )
    if shared:
        print(
            f"shared IPs: {len(shared)} ("
            + ", ".join(f"{ip} x{len(s)}" for ip, s in list(shared.items())[:8])
            + ("..." if len(shared) > 8 else "")
            + ")",
            file=sys.stderr,
        )
    if quality:
        print(
            "IP quality: "
            + ", ".join(f"{k}={v}" for k, v in quality.most_common()),
            file=sys.stderr,
        )
    if anomalies:
        print(
            f"protocol exit anomalies: {len(anomalies)}  "
            f"(first: {anomalies[0][0]} r{anomalies[0][1]} "
            f"{anomalies[0][2]} vs {anomalies[0][3]})",
            file=sys.stderr,
        )
    else:
        print("protocol exit anomalies: 0 (same IP on http + https)", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
