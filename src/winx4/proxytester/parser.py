from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit

from .models import ProxyEntry

DEFAULT_SCHEME = "http"


def parse_line(raw: str) -> ProxyEntry | None:
    line = raw.strip()
    if not line or line.startswith("#"):
        return None
    if "://" in line:
        return _parse_with_scheme(line)
    return _parse_bare(line)


def parse_file(path: str | Path):
    with open(path, encoding="utf-8", errors="ignore") as fh:
        yield from parse_lines(fh)


def parse_lines(fh):
    for raw in fh:
        entry = parse_line(raw)
        if entry is not None:
            yield entry


def _parse_with_scheme(line: str) -> ProxyEntry | None:
    parts = urlsplit(line)
    if not parts.netloc:
        return None
    return _build(parts.scheme, parts.netloc, line)


def _parse_bare(line: str) -> ProxyEntry | None:
    if line.startswith("["):
        host, _, port = line[1:].rpartition("]")
        port = port.lstrip(":")
        if not host or not port.isdigit():
            return None
        return ProxyEntry(line, DEFAULT_SCHEME, host, int(port))
    if "@" in line:
        creds, _, hostport = line.rpartition("@")
        user, _, password = creds.partition(":")
        host, _, port = hostport.rpartition(":")
        if not host or not port.isdigit():
            return None
        return ProxyEntry(
            line, DEFAULT_SCHEME, host, int(port), user or None, password or None
        )
    parts = line.split(":")
    if len(parts) == 2:
        host, port = parts
        user = password = None
    elif len(parts) == 4:
        host, port, user, password = parts
    else:
        return None
    if not host or not port.isdigit():
        return None
    return ProxyEntry(line, DEFAULT_SCHEME, host, int(port), user or None, password or None)


def _build(scheme: str, netloc: str, line: str) -> ProxyEntry | None:
    host, _, port = netloc.rpartition(":")
    if not host or not port.isdigit():
        return None
    username = password = None
    if "@" in host:
        creds, _, host = host.rpartition("@")
        username, _, password = creds.partition(":")
    return ProxyEntry(
        line,
        scheme or DEFAULT_SCHEME,
        host,
        int(port),
        username or None,
        password or None,
    )
