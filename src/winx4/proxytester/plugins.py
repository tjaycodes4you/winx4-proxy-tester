from __future__ import annotations

from collections.abc import Callable
from typing import Any

CHECKERS: dict[str, Callable[..., Any]] = {}
ENRICHERS: dict[str, type] = {}
SINKS: dict[str, type] = {}
TRANSPORTS: dict[str, Callable[..., Any]] = {}


def checker(name: str):
    def register(fn: Callable[..., Any]) -> Callable[..., Any]:
        CHECKERS[name] = fn
        return fn

    return register


def enricher(name: str):
    def register(cls: type) -> type:
        ENRICHERS[name] = cls
        return cls

    return register


def sink(name: str):
    def register(cls: type) -> type:
        SINKS[name] = cls
        return cls

    return register


def transport(name: str):
    def register(fn: Callable[..., Any]) -> Callable[..., Any]:
        TRANSPORTS[name] = fn
        return fn

    return register
