from __future__ import annotations

import csv
import json
from typing import TextIO

from .models import CheckResult
from .plugins import sink as register_sink

CSV_FIELDS = [
    "line",
    "scheme",
    "host",
    "port",
    "status",
    "reason",
    "total_ms",
    "egress_ip",
    "egress_ip2",
    "anonymity",
    "bytes_in",
    "bytes_out",
    "conn_ms",
    "http_version",
    "country",
    "country_iso",
    "city",
    "region",
    "latitude",
    "longitude",
    "timezone",
    "asn",
    "org",
]


def result_to_dict(result: CheckResult) -> dict:
    geo = result.geo
    return {
        "line": result.proxy.line,
        "scheme": result.proxy.scheme,
        "host": result.proxy.host,
        "port": result.proxy.port,
        "status": result.status,
        "reason": result.reason,
        "total_ms": round(result.total_ms, 1) if result.total_ms is not None else "",
        "egress_ip": result.egress_ip,
        "egress_ip2": result.egress_ip2,
        "anonymity": result.anonymity,
        "bytes_in": result.bytes_in,
        "bytes_out": result.bytes_out,
        "conn_ms": round(result.conn_ms, 1) if result.conn_ms is not None else "",
        "http_version": result.http_version,
        "country": geo.country if geo else "",
        "country_iso": geo.country_iso if geo else "",
        "city": geo.city if geo else "",
        "region": geo.region if geo else "",
        "latitude": geo.latitude if geo else "",
        "longitude": geo.longitude if geo else "",
        "timezone": geo.timezone if geo else "",
        "asn": geo.asn if geo else "",
        "org": geo.org if geo else "",
    }


class Sink:
    def write(self, result: CheckResult) -> None:
        raise NotImplementedError

    def close(self) -> None:
        pass


@register_sink("csv")
class CsvSink(Sink):
    def __init__(self, fh: TextIO):
        self._writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        self._writer.writeheader()

    def write(self, result: CheckResult) -> None:
        self._writer.writerow(result_to_dict(result))


@register_sink("jsonl")
class JsonlSink(Sink):
    def __init__(self, fh: TextIO):
        self._fh = fh

    def write(self, result: CheckResult) -> None:
        self._fh.write(json.dumps(result_to_dict(result)) + "\n")


@register_sink("plain")
class PlainSink(Sink):
    def write(self, result: CheckResult) -> None:
        proxy = f"{result.proxy.host}:{result.proxy.port}"
        if result.proxy.scheme != "http":
            proxy = f"{result.proxy.scheme}://{proxy}"
        print(proxy, flush=True)
