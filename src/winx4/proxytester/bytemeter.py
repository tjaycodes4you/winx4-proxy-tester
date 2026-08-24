from __future__ import annotations

import subprocess


def snapshot_systemd(service: str) -> tuple[int, int] | None:
    try:
        out = subprocess.run(
            ["systemctl", "show", "--property=IPIngressBytes",
             "--property=IPEgressBytes", service],
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    values = {}
    for line in out.strip().splitlines():
        key, _, value = line.partition("=")
        if key and value.isdigit():
            values[key] = int(value)
    if "IPIngressBytes" not in values or "IPEgressBytes" not in values:
        return None
    return values["IPIngressBytes"], values["IPEgressBytes"]


def make_provider(service: str):
    if not service:
        return None

    def provider() -> tuple[int, int] | None:
        return snapshot_systemd(service)

    return provider
