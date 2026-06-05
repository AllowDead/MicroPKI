"""Lightweight configuration loader for MicroPKI.

Supports JSON or a small TOML subset with [section] and key = value pairs.
This avoids external dependencies while still providing Sprint 7 --config support.
"""

from __future__ import annotations

import json
import os


def _parse_scalar(value: str):
    value = value.strip()
    if not value:
        return ""
    if value[0:1] in {'"', "'"} and value[-1:] == value[0]:
        return value[1:-1]
    lowered = value.lower()
    if lowered in {"true", "false"}:
        return lowered == "true"
    try:
        if "." in value:
            return float(value)
        return int(value)
    except ValueError:
        return value


def _parse_toml_subset(text: str) -> dict:
    data: dict[str, dict] = {}
    section: str | None = None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip()
            data.setdefault(section, {})
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        target = data.setdefault(section or "default", {})
        target[key] = _parse_scalar(value)
    return data


def load_config(path: str | None) -> dict:
    if not path:
        return {}
    path = os.path.abspath(path)
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    if path.lower().endswith(".json"):
        return json.loads(text)
    return _parse_toml_subset(text)


def section(config: dict, name: str) -> dict:
    return dict(config.get(name, {}) or {})


def apply_config(args) -> None:
    cfg = load_config(getattr(args, "config", None))
    if not cfg:
        return
    rate = section(cfg, "rate_limit")
    audit = section(cfg, "audit")
    ct = section(cfg, "transparency")

    if hasattr(args, "rate_limit") and getattr(args, "rate_limit") == 0 and "requests_per_second" in rate:
        args.rate_limit = float(rate["requests_per_second"])
    if hasattr(args, "rate_burst") and getattr(args, "rate_burst") == 10 and "burst" in rate:
        args.rate_burst = int(rate["burst"])
    if hasattr(args, "log_file") and getattr(args, "log_file") == "./pki/audit/audit.log" and "log_file" in audit:
        args.log_file = str(audit["log_file"])
    if hasattr(args, "chain_file") and getattr(args, "chain_file") == "./pki/audit/chain.dat" and "chain_file" in audit:
        args.chain_file = str(audit["chain_file"])
    if hasattr(args, "ct_log") and getattr(args, "ct_log") == "./pki/audit/ct.log" and "ct_log" in ct:
        args.ct_log = str(ct["ct_log"])
