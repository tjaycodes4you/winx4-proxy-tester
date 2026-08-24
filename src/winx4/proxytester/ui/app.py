from __future__ import annotations

import asyncio
import datetime
import io
import json
import os
import time
from collections import defaultdict

from nicegui import events, ui

from ..bytemeter import make_provider
from ..cli import DEFAULT_ECHO, _rotation_summary
from ..ebpfmeter import DEFAULT_SCRIPT, ConnMeter
from ..models import CheckResult
from ..parser import parse_lines
from ..plugins import ENRICHERS, SINKS, TRANSPORTS
from ..rotation import RotationStudy, rotation_study

CYAN = "#00f0ff"
GREEN = "#39ff14"
RED = "#ff3860"

GEO_CITY_DEFAULT = os.environ.get("WX4_GEO_CITY", "")
GEO_ASN_DEFAULT = os.environ.get("WX4_GEO_ASN", "")
BYTES_SERVICE = os.environ.get("WX4_BYTES_SERVICE", "")
EBPF_ENABLED = os.environ.get("WX4_EBPF", "") == "1"
EBPF_SCRIPT = os.environ.get("WX4_EBPF_SCRIPT", DEFAULT_SCRIPT)

CSS = """
<style>
body { background: #070b12; font-family: 'Cascadia Mono', Consolas, monospace; }
.title { color: #00f0ff; text-shadow: 0 0 8px #00f0ff88, 0 0 28px #00f0ff44; letter-spacing: .25em; }
.panel { background: #0b1120ee !important; border: 1px solid #00f0ff33 !important; box-shadow: 0 0 14px #00f0ff22, inset 0 0 24px #00f0ff0a !important; }
.neon-btn { border: 1px solid; background: transparent; font-weight: 700; letter-spacing: .15em; text-transform: uppercase; }
.neon-btn.cyan { color: #00f0ff; border-color: #00f0ff; box-shadow: 0 0 10px #00f0ff55 inset, 0 0 16px #00f0ff33; }
.neon-btn.cyan:hover { background: #00f0ff11; }
.neon-btn.red { color: #ff3860; border-color: #ff3860; box-shadow: 0 0 10px #ff386044 inset; }
.stat-card { background: #0b1120ee; border: 1px solid #00f0ff22; padding: 10px 14px; min-width: 110px; }
.upload-compact { width: 130px; height: 34px; }
.upload-compact .q-uploader__header { display: flex; justify-content: center; align-items: center; background: transparent; }
.upload-compact .q-uploader__list { display: none; }
.upload-compact .q-uploader { position: relative; width: 130px; height: 34px; border: 1px solid #00f0ff55; border-radius: 4px; }
.upload-compact .q-uploader__input { position: absolute; inset: 0; width: 100% !important; height: 100% !important; cursor: pointer; }
.upload-compact .q-uploader__content { display: flex; justify-content: center; align-items: center; font-size: 11px; letter-spacing: .15em; color: #00f0ff; }
.upload-compact .q-uploader__content > div { display: none; }
.stat-label { color: #00f0ff88; font-size: 10px; letter-spacing: .2em; text-transform: uppercase; }
.stat-value { color: #e8f6ff; font-size: 22px; font-weight: 700; text-shadow: 0 0 10px #00f0ff66; }
.scanlines::before { content: ""; position: fixed; inset: 0; pointer-events: none; z-index: 50;
  background: repeating-linear-gradient(0deg, transparent 0 2px, rgba(0,240,255,.015) 2px 4px); }
.ag-cell.ok { color: #39ff14 !important; text-shadow: 0 0 6px #39ff1488; }
.ag-cell.dead { color: #ff3860 !important; }
.ag-cell.flip { color: #ff2bd6 !important; text-shadow: 0 0 6px #ff2bd688; }
.q-field--focused .q-field__control { box-shadow: 0 0 10px #00f0ff33 !important; }
.q-radio__inner--truthy { color: #00f0ff !important; }
.q-radio__label { color: #a7c8dd !important; letter-spacing: .1em; text-transform: uppercase; font-size: 11px; }
</style>
"""

COLUMNS = [
    {"headerName": "proxy", "field": "proxy", "minWidth": 160},
    {"headerName": "scheme", "field": "scheme", "width": 90},
    {"headerName": "status", "field": "status", "width": 80,
     "cellClassRules": {"ok": 'x === "ok"', "dead": 'x !== "ok"'}},
    {"headerName": "reason", "field": "reason", "width": 100},
    {"headerName": "ms", "field": "ms", "width": 70},
    {"headerName": "egress ip", "field": "ip", "width": 140},
    {"headerName": "ip2", "field": "ip2", "width": 140},
    {"headerName": "anon", "field": "anon", "width": 110},
    {"headerName": "bytes in", "field": "bin", "width": 90},
    {"headerName": "bytes out", "field": "bout", "width": 90},
    {"headerName": "country", "field": "country", "width": 140},
    {"headerName": "org", "field": "org", "minWidth": 220},
]

HIST_COLUMNS = [
    {"headerName": "session", "field": "proxy", "minWidth": 220},
    {"headerName": "pool", "field": "pool", "width": 70},
    {"headerName": "flips", "field": "flips", "width": 70,
     "cellClassRules": {"flip": 'x > 0'}},
    {"headerName": "egress sequence (per round)", "field": "seq", "minWidth": 400},
]


@ui.page("/")
def index():
    state = {
        "entries": [],
        "source": None,
        "rows": [],
        "results": [],
        "pending": [],
        "history": [],
        "stats": None,
        "running": False,
        "cancel": None,
        "enricher": None,
        "last_done": 0,
        "mode": "single",
        "study": None,
        "countdown_until": None,
    }
    ui.add_head_html(CSS)

    def flush() -> None:
        if state["pending"]:
            for result in state["pending"]:
                geo = result.geo
                state["rows"].append({
                    "proxy": f"{result.proxy.host}:{result.proxy.port}",
                    "scheme": result.proxy.scheme,
                    "status": result.status,
                    "reason": result.reason or "",
                    "ms": round(result.total_ms) if result.total_ms is not None else "",
                    "ip": result.egress_ip or "",
                    "ip2": result.egress_ip2 or "",
                    "anon": result.anonymity or "",
                    "bin": result.bytes_in if result.bytes_in is not None else "",
                    "bout": result.bytes_out if result.bytes_out is not None else "",
                    "country": geo.country if geo else "",
                    "org": geo.org if geo else "",
                })
            state["pending"] = []
            grid.options["rowData"] = state["rows"]
            grid.update()
        stats = state["stats"]
        if stats is None:
            return
        if stats.bytes_in is not None:
            stat_bin.set_text(f"{stats.bytes_in / 1048576:.2f}")
            stat_bout.set_text(f"{stats.bytes_out / 1048576:.2f}")
            stat_total.set_text(f"{(stats.bytes_in + stats.bytes_out) / 1048576:.2f}")
        if stats.overhead_in is not None and stats.payload_in is not None:
            total = stats.bytes_in + stats.bytes_out
            overhead = stats.overhead_in + stats.overhead_out
            stat_ovh.set_text(f"{overhead / total * 100:.1f}%" if total else "0.0%")
        if stats.done == state["last_done"]:
            return
        state["last_done"] = stats.done
        stat_checked.set_text(f"{stats.done:,}")
        stat_alive.set_text(f"{stats.alive:,}")
        stat_dead.set_text(f"{stats.done - stats.alive:,}")
        stat_cps.set_text(f"{stats.checks_per_sec:,.0f}")
        stat_avg.set_text(f"{stats.avg_latency_ms:,.0f}")
        stat_rate.set_text(f"{(stats.alive / stats.done * 100) if stats.done else 0:.1f}%")
        state["history"].append([int(time.time() * 1000), round(stats.checks_per_sec, 1)])
        chart.options["series"][0]["data"] = state["history"][-240:]
        chart.update()

    def on_result(result: CheckResult, stats) -> None:
        state["stats"] = stats
        state["pending"].append(result)
        state["results"].append(result)

    async def handle_upload(e: events.UploadEventArguments) -> None:
        content = await e.file.read()
        text = content.decode("utf-8", errors="ignore")
        state["entries"] = list(parse_lines(io.StringIO(text)))
        state["source"] = "upload"
        count_lbl.set_text(f"{len(state['entries']):,} proxies loaded: {getattr(e.file, 'name', '')}")

    def set_led(color: str) -> None:
        led.style(f"color:{color}; text-shadow: 0 0 10px {color}; font-size: 14px")

    def rebuild_history(study: RotationStudy) -> None:
        per = study.per_session()
        flip_counts: dict[str, int] = defaultdict(int)
        for line, *_ in study.rotation_events():
            flip_counts[line] += 1
        rows = []
        for line, ips in per.items():
            pool = len({ip for ip in ips if ip})
            seq = " → ".join(ip or "·" for ip in ips[-12:])
            rows.append({"proxy": line, "pool": pool, "flips": flip_counts[line], "seq": seq})
        hist_grid.options["rowData"] = rows
        hist_grid.update()

    def on_round(rnd, study: RotationStudy) -> None:
        state["study"] = study
        round_lbl.set_text(f"ROUND {rnd.index + 1}/{int(rounds_input.value or 20)}")
        state["countdown_until"] = (
            time.monotonic() + float(interval_input.value or 60)
            if rnd.index + 1 < int(rounds_input.value or 20)
            else None
        )
        rebuild_history(study)

    def render_analysis(study: RotationStudy) -> None:
        if len(study.rounds) < 1:
            return
        analysis_box.visible = True
        events = study.rotation_events()
        sessions_with = len({line for line, *_ in events})
        pool_sizes = study.pool_sizes().values()
        shared = study.shared_ips()
        anomalies = study.protocol_anomalies()
        quality = study.quality_breakdown()
        a_sessions.set_text(f"{len(study.entries)}")
        a_flips.set_text(f"{len(events)}")
        a_pool.set_text(
            f"{min(pool_sizes)}/{max(pool_sizes)}"
            if pool_sizes else "-"
        )
        a_shared.set_text(f"{len(shared)}")
        a_anom.set_text(f"{len(anomalies)}")
        a_quality.set_text(
            ", ".join(f"{k}:{v}" for k, v in quality.most_common()) or "-"
        )
        hold = study.hold_distribution()
        buckets = sorted(hold.items())
        cats = []
        vals = []
        for n, c in buckets:
            label = f"{n}r" if n < 4 else "4r+"
            cats.append(f"{label} (~{min(n, 4) * study.interval_s:.0f}s)")
            vals.append(c if n < 4 else sum(c for k, c in buckets if k >= 4))
        hold_chart.options["xAxis"]["data"] = cats
        hold_chart.options["series"][0]["data"] = vals
        hold_chart.update()
        flips = study.flips_per_round()
        flip_chart.options["xAxis"]["data"] = [f"r{i}" for i in range(1, len(study.rounds))]
        flip_chart.options["series"][0]["data"] = [flips.get(i, 0) for i in range(1, len(study.rounds))]
        flip_chart.update()

    def tick() -> None:
        if state["running"] and state["mode"] == "rotation":
            if state["countdown_until"]:
                remaining = state["countdown_until"] - time.monotonic()
                countdown_lbl.set_text(
                    f"next round in {remaining:.0f}s" if remaining > 0 else "checking…"
                )
            else:
                countdown_lbl.set_text("checking…")
        else:
            countdown_lbl.set_text("")

    async def start_run() -> None:
        if state["running"]:
            return
        if state["source"] == "upload":
            entries = state["entries"]
        else:
            text = textarea.value.strip()
            if not text:
                ui.notify("paste a proxy list or drop a file", type="warning")
                return
            entries = list(parse_lines(io.StringIO(text)))
        if not entries:
            ui.notify("no proxies parsed from list", type="warning")
            return
        geo = GEO_CITY_DEFAULT or None
        asn = GEO_ASN_DEFAULT or None
        enricher = ENRICHERS["geolite2"](geo, asn) if (geo or asn) else None
        state.update(
            entries=entries,
            source=state["source"] or "paste",
            rows=[],
            results=[],
            pending=[],
            history=[],
            stats=None,
            cancel=asyncio.Event(),
            enricher=enricher,
            last_done=0,
            study=None,
            countdown_until=None,
        )
        count_lbl.set_text(f"{len(entries):,} proxies loaded")
        grid.options["rowData"] = []
        grid.update()
        hist_grid.options["rowData"] = []
        hist_grid.update()
        analysis_box.visible = False
        if state["mode"] == "rotation":
            round_row.visible = True
            hist_row.visible = True
        spinner.visible = True
        run_btn.disable()
        stop_btn.enable()
        set_led(GREEN)
        state["running"] = True

        async def job() -> None:
            try:
                if state["mode"] == "rotation":
                    sample = int(sample_input.value or 0) or len(entries)
                    study = await rotation_study(
                        entries[:sample],
                        echo_input.value,
                        int(concurrency_input.value or 1000),
                        timeout=datetime.timedelta(seconds=float(timeout_input.value or 3.0)),
                        rounds=int(rounds_input.value or 20),
                        interval_s=float(interval_input.value or 60),
                        echo2_url=echo2_input.value.strip() or None,
                        enricher=enricher,
                        byte_provider=make_provider(BYTES_SERVICE),
                        cancel=state["cancel"],
                        on_round=on_round,
                    )
                    state["study"] = study
                    state["stats"] = study.rounds[-1].stats if study.rounds else None
                else:
                    stats = await TRANSPORTS["local"](
                        entries,
                        echo_input.value,
                        int(concurrency_input.value or 1000),
                        timeout=datetime.timedelta(seconds=float(timeout_input.value or 3.0)),
                        on_result=on_result,
                        dedupe=True,
                        enricher=enricher,
                        cancel=state["cancel"],
                        echo2_url=echo2_input.value.strip() or None,
                        byte_provider=make_provider(BYTES_SERVICE),
                        conn_meter=ConnMeter(EBPF_SCRIPT, os.getpid()) if EBPF_ENABLED else None,
                    )
                    state["stats"] = stats
            finally:
                state["running"] = False
                spinner.visible = False
                run_btn.enable()
                stop_btn.disable()
                set_led(RED)
                if enricher:
                    enricher.close()
                flush()
                study = state["study"]
                if state["mode"] == "rotation" and study and len(study.rounds) >= 2:
                    render_analysis(study)
                    round_lbl.set_text(
                        f"STUDY DONE — {len(study.rounds)} ROUNDS"
                        + (" (cancelled)" if study.cancelled else "")
                    )
                    ui.notify(
                        f"study done — {len(study.rotation_events())} rotations "
                        f"across {len(study.rounds)} rounds"
                    )
                elif state["stats"]:
                    s = state["stats"]
                    ui.notify(f"done — {s.alive:,} alive / {s.done - s.alive:,} dead")

        asyncio.create_task(job())

    def export_csv(alive_only: bool) -> None:
        buf = io.StringIO()
        sink = SINKS["csv"](buf)
        for result in state["results"]:
            if alive_only and result.status != "ok":
                continue
            sink.write(result)
        ui.download(buf.getvalue().encode("utf-8"), f"winx4-{'alive-' if alive_only else ''}proxies.csv")

    def export_jsonl() -> None:
        buf = io.StringIO()
        sink = SINKS["jsonl"](buf)
        for result in state["results"]:
            sink.write(result)
        ui.download(buf.getvalue().encode("utf-8"), "winx4-proxies.jsonl")

    def export_study_json() -> None:
        study = state["study"]
        if study:
            ui.download(
                json.dumps(_rotation_summary(study), indent=2).encode("utf-8"),
                "winx4-rotation-study.json",
            )

    def switch_mode(e) -> None:
        state["mode"] = e.value
        rotation_card.visible = e.value == "rotation"
        round_row.visible = False
        hist_row.visible = False
        analysis_box.visible = False

    with ui.column().classes("w-full max-w-[1500px] mx-auto p-6 gap-6 scanlines"):
        with ui.row().classes("w-full items-center justify-between"):
            ui.label("WINX4 // PROXY TESTER").classes("title text-4xl font-bold")
            with ui.row().classes("items-center gap-2"):
                led = ui.icon("circle")
                ui.label("ENGINE").classes("text-xs tracking-[.3em] text-cyan-400/60")

        with ui.row().classes("w-full gap-6 items-start"):
            with ui.column().classes("w-[380px] gap-4"):
                with ui.card().classes("panel w-full p-4").tight():
                    with ui.column().classes("gap-3 p-4"):
                        with ui.row().classes("w-full items-center justify-between"):
                            ui.label("PROXY LIST").classes("text-xs tracking-[.3em] text-cyan-400/70")
                            ui.upload(on_upload=handle_upload, auto_upload=True, label="LOAD FILE") \
                                .classes("upload-compact")
                        textarea = ui.textarea("paste proxies (one per line)") \
                            .classes("w-full").style("font-family: monospace; font-size: 12px")
                        count_lbl = ui.label("").classes("text-xs text-cyan-400/70")
                        echo_input = ui.input("echo url", value=DEFAULT_ECHO).classes("w-full")
                        echo2_input = ui.input("echo url 2 (optional)").classes("w-full") \
                            .tooltip("Some proxies exit through a different IP for HTTP vs "
                                     "HTTPS. Set the second URL (e.g. http://ip.motn.online/) "
                                     "and each proxy is tested against both, capturing both egress IPs.")
                        with ui.row().classes("w-full gap-2"):
                            concurrency_input = ui.number("concurrency", value=1000, min=1, max=50000) \
                                .classes("w-1/2")
                            timeout_input = ui.number("timeout (s)", value=3.0, min=0.1, step=0.5) \
                                .classes("w-1/2")
                        ui.label("MODE").classes("text-xs tracking-[.3em] text-cyan-400/70")
                        mode = ui.radio({"single": "SINGLE PASS", "rotation": "ROTATION STUDY"},
                                        value="single", on_change=switch_mode) \
                            .props("inline").classes("w-full")
                        with ui.column().classes("gap-2 w-full") as rotation_card:
                            with ui.row().classes("w-full gap-2"):
                                rounds_input = ui.number("rounds", value=20, min=2, max=500) \
                                    .classes("w-1/3")
                                interval_input = ui.number("interval (s)", value=60, min=1, max=3600) \
                                    .classes("w-1/3")
                                sample_input = ui.number("sample", value=40, min=1, max=100000) \
                                    .classes("w-1/3")
                            ui.label("samples the first N proxies every interval "
                                     "to observe egress IP rotation") \
                                .classes("text-[10px] text-cyan-400/60")
                        rotation_card.visible = False
                        with ui.row().classes("w-full gap-2 items-center"):
                            run_btn = ui.button("RUN", on_click=start_run).classes("neon-btn cyan flex-1")
                            stop_btn = ui.button("STOP", on_click=lambda: state["cancel"].set() if state["cancel"] else None) \
                                .classes("neon-btn red")
                            stop_btn.disable()
                            spinner = ui.spinner("puff", size="md", color=CYAN)
                            spinner.visible = False

            with ui.column().classes("flex-1 gap-4"):
                with ui.row().classes("w-full gap-3 flex-wrap"):
                    stat_checked = _stat_card("checked", "0",
                                              "Total proxies tested so far in this run")
                    stat_alive = _stat_card("alive", "0",
                                            "Proxies that passed the echo check")
                    stat_dead = _stat_card("dead", "0",
                                           "Proxies that failed, timed out, or were cancelled")
                    stat_cps = _stat_card("checks/s", "0",
                                          "Checks completed per second")
                    stat_avg = _stat_card("avg ms", "0",
                                          "Average total time per check, including the second echo")
                    stat_rate = _stat_card("alive %", "0",
                                           "Share of checks that passed")
                    stat_bin = _stat_card("mib in", "-",
                                          "Exact wire bytes received by this server during the run "
                                          "(IP layer: headers, handshakes, retransmits included)")
                    stat_bout = _stat_card("mib out", "-",
                                           "Exact wire bytes sent by this server during the run "
                                           "(IP layer: headers, handshakes, retransmits included)")
                    stat_total = _stat_card("mib total", "-",
                                            "Sum of bytes in + out for this run")
                    stat_ovh = _stat_card("wire ovh %", "-",
                                          "Share of wire bytes not visible as payload: "
                                          "TCP/IP headers, SYN retries, ACKs")
                with ui.row().classes("w-full items-center gap-4") as round_row:
                    round_lbl = ui.label("").classes("stat-value")
                    countdown_lbl = ui.label("").classes("text-xs text-cyan-400/70")
                round_row.visible = False
                chart = ui.echart({
                    "backgroundColor": "transparent",
                    "grid": {"left": 44, "right": 16, "top": 10, "bottom": 22},
                    "xAxis": {"type": "time", "axisLine": {"lineStyle": {"color": "#00f0ff44"}},
                              "axisLabel": {"color": "#00f0ff88", "hideOverlap": True}},
                    "yAxis": {"type": "value", "splitLine": {"lineStyle": {"color": "#00f0ff11"}},
                              "axisLabel": {"color": "#00f0ff88"}},
                    "series": [{"type": "line", "showSymbol": False,
                                "lineStyle": {"color": CYAN, "width": 2},
                                "areaStyle": {"color": "rgba(0,240,255,0.08)"}, "data": []}],
                }).classes("w-full h-36")
                grid = ui.aggrid({"columnDefs": COLUMNS, "rowData": []}, theme="quartz") \
                    .classes("w-full h-[40vh]")
                with ui.column().classes("w-full gap-3") as hist_row:
                    ui.label("PER-SESSION EGRESS HISTORY").classes("text-xs tracking-[.3em] text-cyan-400/70")
                    hist_grid = ui.aggrid({"columnDefs": HIST_COLUMNS, "rowData": []}, theme="quartz") \
                        .classes("w-full h-[24vh]")
                hist_row.visible = False
                with ui.column().classes("w-full gap-3 panel p-4") as analysis_box:
                    ui.label("ROTATION ANALYSIS").classes("text-xs tracking-[.3em] text-cyan-400/70")
                    with ui.row().classes("w-full gap-3 flex-wrap"):
                        a_sessions = _stat_card("sessions", "-", "Total sessions in the study")
                        a_flips = _stat_card("rotations", "-", "Total egress IP flips observed")
                        a_pool = _stat_card("pool min/max", "-", "Smallest and largest per-session IP pool")
                        a_shared = _stat_card("shared ips", "-", "IPs seen on more than one session")
                        a_anom = _stat_card("proto anomalies", "-", "Sessions with different http vs https egress")
                        a_quality = _stat_card("quality", "-", "DC vs residential classification from ASN org")
                    hold_chart = ui.echart({
                        "backgroundColor": "transparent",
                        "grid": {"left": 44, "right": 16, "top": 10, "bottom": 26},
                        "xAxis": {"type": "category", "axisLine": {"lineStyle": {"color": "#00f0ff44"}},
                                  "axisLabel": {"color": "#00f0ff88", "rotate": 30}},
                        "yAxis": {"type": "value", "splitLine": {"lineStyle": {"color": "#00f0ff11"}},
                                  "axisLabel": {"color": "#00f0ff88"}},
                        "series": [{"type": "bar", "itemStyle": {"color": CYAN},
                                    "data": []}],
                    }).classes("w-full h-36")
                    ui.label("FLIPS PER ROUND (global sync signal)") \
                        .classes("text-[10px] tracking-[.2em] text-cyan-400/60")
                    flip_chart = ui.echart({
                        "backgroundColor": "transparent",
                        "grid": {"left": 44, "right": 16, "top": 10, "bottom": 26},
                        "xAxis": {"type": "category", "axisLine": {"lineStyle": {"color": "#00f0ff44"}},
                                  "axisLabel": {"color": "#00f0ff88"}},
                        "yAxis": {"type": "value", "splitLine": {"lineStyle": {"color": "#00f0ff11"}},
                                  "axisLabel": {"color": "#00f0ff88"}},
                        "series": [{"type": "line", "showSymbol": True, "symbolSize": 6,
                                    "lineStyle": {"color": "#ff2bd6", "width": 2},
                                    "itemStyle": {"color": "#ff2bd6"},
                                    "data": []}],
                    }).classes("w-full h-28")
                analysis_box.visible = False
                with ui.row().classes("w-full gap-2"):
                    ui.button("CSV ALL", on_click=lambda: export_csv(False)).classes("neon-btn cyan")
                    ui.button("CSV ALIVE", on_click=lambda: export_csv(True)).classes("neon-btn cyan")
                    ui.button("JSONL", on_click=export_jsonl).classes("neon-btn cyan")
                    ui.button("STUDY JSON", on_click=export_study_json).classes("neon-btn cyan")

    set_led(RED)
    ui.timer(0.5, flush)
    ui.timer(1.0, tick)


def _stat_card(label: str, value: str, tooltip: str):
    card = ui.column().classes("stat-card gap-0").tooltip(tooltip)
    with card:
        ui.label(label).classes("stat-label")
        value_lbl = ui.label(value).classes("stat-value")
    return value_lbl


def main() -> None:
    ui.run(
        host=os.environ.get("WX4_UI_HOST", "127.0.0.1"),
        port=int(os.environ.get("WX4_UI_PORT", "8901")),
        title="WINX4 // PROXY TESTER",
        dark=True,
        reload=False,
        show=False,
    )
