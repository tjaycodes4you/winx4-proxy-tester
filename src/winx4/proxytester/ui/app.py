from __future__ import annotations

import asyncio
import datetime
import io
import os
import time

from nicegui import events, ui

from ..bytemeter import make_provider
from ..cli import DEFAULT_ECHO
from ..models import CheckResult
from ..parser import parse_lines
from ..plugins import ENRICHERS, SINKS, TRANSPORTS

CYAN = "#00f0ff"
GREEN = "#39ff14"
RED = "#ff3860"

GEO_CITY_DEFAULT = os.environ.get("WX4_GEO_CITY", "")
GEO_ASN_DEFAULT = os.environ.get("WX4_GEO_ASN", "")
BYTES_SERVICE = os.environ.get("WX4_BYTES_SERVICE", "")

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
.stat-label { color: #00f0ff88; font-size: 10px; letter-spacing: .2em; text-transform: uppercase; }
.stat-value { color: #e8f6ff; font-size: 22px; font-weight: 700; text-shadow: 0 0 10px #00f0ff66; }
.scanlines::before { content: ""; position: fixed; inset: 0; pointer-events: none; z-index: 50;
  background: repeating-linear-gradient(0deg, transparent 0 2px, rgba(0,240,255,.015) 2px 4px); }
.ag-cell.ok { color: #39ff14 !important; text-shadow: 0 0 6px #39ff1488; }
.ag-cell.dead { color: #ff3860 !important; }
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
    {"headerName": "country", "field": "country", "width": 140},
    {"headerName": "org", "field": "org", "minWidth": 220},
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
                    "country": geo.country if geo else "",
                    "org": geo.org if geo else "",
                })
            state["pending"] = []
            grid.options["rowData"] = state["rows"]
            grid.update()
        stats = state["stats"]
        if stats is None:
            return
        if stats.done == state["last_done"]:
            return
        state["last_done"] = stats.done
        stat_checked.set_text(f"{stats.done:,}")
        stat_alive.set_text(f"{stats.alive:,}")
        stat_dead.set_text(f"{stats.done - stats.alive:,}")
        stat_cps.set_text(f"{stats.checks_per_sec:,.0f}")
        stat_avg.set_text(f"{stats.avg_latency_ms:,.0f}")
        stat_rate.set_text(f"{(stats.alive / stats.done * 100) if stats.done else 0:.1f}%")
        if stats.bytes_in is not None:
            stat_bin.set_text(f"{stats.bytes_in / 1048576:.2f}")
            stat_bout.set_text(f"{stats.bytes_out / 1048576:.2f}")
        state["history"].append([int(time.time() * 1000), round(stats.checks_per_sec, 1)])
        chart.options["series"][0]["data"] = state["history"][-240:]
        chart.update()

    def on_result(result: CheckResult, stats) -> None:
        state["stats"] = stats
        state["pending"].append(result)
        state["results"].append(result)

    async def handle_upload(e: events.UploadEventArguments) -> None:
        content = await e.content.read()
        text = content.decode("utf-8", errors="ignore")
        state["entries"] = list(parse_lines(io.StringIO(text)))
        state["source"] = "upload"
        count_lbl.set_text(f"{len(state['entries']):,} proxies loaded: {e.name}")

    def set_led(color: str) -> None:
        led.style(f"color:{color}; text-shadow: 0 0 10px {color}; font-size: 14px")

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
        geo = geo_input.value.strip() if geo_input.value else None
        asn = asn_input.value.strip() if asn_input.value else None
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
        )
        count_lbl.set_text(f"{len(entries):,} proxies loaded")
        grid.options["rowData"] = []
        grid.update()
        spinner.visible = True
        run_btn.disable()
        stop_btn.enable()
        set_led(GREEN)
        state["running"] = True

        async def job() -> None:
            try:
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
                if state["stats"]:
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
                        ui.label("PROXY LIST").classes("text-xs tracking-[.3em] text-cyan-400/70")
                        textarea = ui.textarea("paste proxies (one per line)") \
                            .classes("w-full").style("font-family: monospace; font-size: 12px")
                        ui.upload(on_upload=handle_upload, auto_upload=True, label="DROP LIST FILE") \
                            .classes("w-full")
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
                        geo_input = ui.input("GeoLite2-City.mmdb (optional)", value=GEO_CITY_DEFAULT) \
                            .classes("w-full")
                        asn_input = ui.input("GeoLite2-ASN.mmdb (optional)", value=GEO_ASN_DEFAULT) \
                            .classes("w-full")
                        with ui.row().classes("w-full gap-2 items-center"):
                            run_btn = ui.button("RUN", on_click=start_run).classes("neon-btn cyan flex-1")
                            stop_btn = ui.button("STOP", on_click=lambda: state["cancel"].set() if state["cancel"] else None) \
                                .classes("neon-btn red")
                            stop_btn.disable()
                            spinner = ui.spinner("puff", size="md", color=CYAN)
                            spinner.visible = False

            with ui.column().classes("flex-1 gap-4"):
                with ui.row().classes("w-full gap-3"):
                    stat_checked = _stat_card("checked", "0")
                    stat_alive = _stat_card("alive", "0")
                    stat_dead = _stat_card("dead", "0")
                    stat_cps = _stat_card("checks/s", "0")
                    stat_avg = _stat_card("avg ms", "0")
                    stat_rate = _stat_card("alive %", "0")
                    stat_bin = _stat_card("mib in", "-")
                    stat_bout = _stat_card("mib out", "-")
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
                    .classes("w-full h-[52vh]")
                with ui.row().classes("w-full gap-2"):
                    ui.button("CSV ALL", on_click=lambda: export_csv(False)).classes("neon-btn cyan")
                    ui.button("CSV ALIVE", on_click=lambda: export_csv(True)).classes("neon-btn cyan")
                    ui.button("JSONL", on_click=export_jsonl).classes("neon-btn cyan")

    set_led(RED)
    ui.timer(0.5, flush)


def _stat_card(label: str, value: str):
    with ui.column().classes("stat-card gap-0"):
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
