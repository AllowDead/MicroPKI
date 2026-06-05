"""Structured audit logging with SHA-256 hash chaining for MicroPKI."""

from __future__ import annotations

import csv
import datetime as _dt
import hashlib
import io
import json
import os
import sys
from typing import Iterable, Optional

ZERO_HASH = "0" * 64
DEFAULT_AUDIT_LOG = "./pki/audit/audit.log"
DEFAULT_CHAIN_FILE = "./pki/audit/chain.dat"


def utc_now_iso_micro() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def audit_dir_for_pki_root(pki_root: str = "./pki") -> str:
    return os.path.join(os.path.abspath(pki_root), "audit")


def default_log_path(pki_root: str = "./pki") -> str:
    return os.path.join(audit_dir_for_pki_root(pki_root), "audit.log")


def default_chain_path(pki_root: str = "./pki") -> str:
    return os.path.join(audit_dir_for_pki_root(pki_root), "chain.dat")


def _canonical_json(obj: dict) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _hash_entry_without_hash(entry: dict) -> str:
    data = json.loads(json.dumps(entry, ensure_ascii=False))
    integrity = data.setdefault("integrity", {})
    integrity.pop("hash", None)
    return hashlib.sha256(_canonical_json(data).encode("utf-8")).hexdigest()


def _read_last_hash_from_chain(chain_file: str) -> str:
    if not os.path.isfile(chain_file):
        return ZERO_HASH
    last = ""
    with open(chain_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                last = line
    return last if len(last) == 64 else ZERO_HASH


def _read_last_hash_from_log(log_file: str) -> str:
    if not os.path.isfile(log_file):
        return ZERO_HASH
    last = ""
    with open(log_file, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                last = line
    if not last:
        return ZERO_HASH
    try:
        entry = json.loads(last)
        return entry.get("integrity", {}).get("hash") or ZERO_HASH
    except json.JSONDecodeError:
        return ZERO_HASH


class AuditLogger:
    """Append-only NDJSON audit logger.

    The event hash is SHA-256 over canonical JSON of the event without
    ``integrity.hash``. The ``prev_hash`` value links to the previous event hash.
    """

    def __init__(self, log_file: str = DEFAULT_AUDIT_LOG, chain_file: str | None = None):
        self.log_file = os.path.abspath(log_file)
        self.chain_file = os.path.abspath(chain_file or os.path.join(os.path.dirname(self.log_file), "chain.dat"))
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
        os.makedirs(os.path.dirname(self.chain_file), exist_ok=True)

    def _previous_hash(self) -> str:
        chain_hash = _read_last_hash_from_chain(self.chain_file)
        if chain_hash != ZERO_HASH:
            return chain_hash
        return _read_last_hash_from_log(self.log_file)

    def log_event(
        self,
        operation: str,
        status: str,
        message: str,
        level: str = "AUDIT",
        metadata: Optional[dict] = None,
    ) -> dict:
        metadata = dict(metadata or {})
        # Do not persist obvious secrets if a caller accidentally passes them.
        for key in list(metadata.keys()):
            if any(marker in key.lower() for marker in ("private", "pass", "secret", "token")):
                metadata[key] = "[redacted]"
        prev_hash = self._previous_hash()
        entry = {
            "timestamp": utc_now_iso_micro(),
            "level": level,
            "operation": operation,
            "status": status,
            "message": message,
            "metadata": metadata,
            "integrity": {"prev_hash": prev_hash},
        }
        entry["integrity"]["hash"] = _hash_entry_without_hash(entry)
        line = _canonical_json(entry)
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(line + "\n")
        with open(self.chain_file, "a", encoding="utf-8") as f:
            f.write(entry["integrity"]["hash"] + "\n")
        return entry


def get_audit_logger(pki_root: str = "./pki", log_file: str | None = None, chain_file: str | None = None) -> AuditLogger:
    return AuditLogger(log_file or default_log_path(pki_root), chain_file or default_chain_path(pki_root))


def load_entries(log_file: str) -> list[dict]:
    entries: list[dict] = []
    if not os.path.exists(log_file):
        return entries
    with open(log_file, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
                entry["_line"] = line_no
                entries.append(entry)
            except json.JSONDecodeError as exc:
                entries.append({"_line": line_no, "_parse_error": str(exc), "raw": line.rstrip("\n")})
    return entries


def verify_log(log_file: str = DEFAULT_AUDIT_LOG, chain_file: str | None = None) -> tuple[bool, str, Optional[int]]:
    log_file = os.path.abspath(log_file)
    chain_file = os.path.abspath(chain_file or os.path.join(os.path.dirname(log_file), "chain.dat"))
    if not os.path.exists(log_file):
        return False, f"Audit log not found: {log_file}", None
    prev = ZERO_HASH
    computed_hashes: list[str] = []
    with open(log_file, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                entry = json.loads(stripped)
            except json.JSONDecodeError:
                return False, f"Corrupted JSON at entry {line_no}", line_no
            integrity = entry.get("integrity") or {}
            if integrity.get("prev_hash") != prev:
                return False, f"Hash chain break at entry {line_no}: prev_hash mismatch", line_no
            expected = _hash_entry_without_hash(entry)
            if integrity.get("hash") != expected:
                return False, f"Tampering detected at entry {line_no}: hash mismatch", line_no
            prev = expected
            computed_hashes.append(expected)

    if os.path.exists(chain_file):
        with open(chain_file, "r", encoding="utf-8") as f:
            chain_hashes = [line.strip() for line in f if line.strip()]
        if chain_hashes != computed_hashes:
            first = None
            for idx, (a, b) in enumerate(zip(chain_hashes, computed_hashes), start=1):
                if a != b:
                    first = idx
                    break
            if first is None and len(chain_hashes) != len(computed_hashes):
                first = min(len(chain_hashes), len(computed_hashes)) + 1
            return False, f"chain.dat mismatch at entry {first}", first
    return True, f"Audit log integrity OK: {len(computed_hashes)} entries", None


def _iso_in_range(value: str, start: str | None, end: str | None) -> bool:
    if start and value < start:
        return False
    if end and value > end:
        return False
    return True


def query_entries(
    log_file: str = DEFAULT_AUDIT_LOG,
    start: str | None = None,
    end: str | None = None,
    level: str | None = None,
    operation: str | None = None,
    serial: str | None = None,
) -> list[dict]:
    results = []
    wanted_level = level.upper() if level else None
    wanted_operation = operation.lower() if operation else None
    wanted_serial = serial.upper().lstrip("0") if serial else None
    for entry in load_entries(log_file):
        if "_parse_error" in entry:
            results.append(entry)
            continue
        if not _iso_in_range(entry.get("timestamp", ""), start, end):
            continue
        if wanted_level and entry.get("level", "").upper() != wanted_level:
            continue
        if wanted_operation and wanted_operation not in entry.get("operation", "").lower():
            continue
        if wanted_serial:
            meta = entry.get("metadata") or {}
            entry_serial = str(meta.get("serial", "")).upper().lstrip("0")
            if entry_serial != wanted_serial:
                continue
        results.append(entry)
    return results


def format_entries(entries: Iterable[dict], output_format: str = "table") -> str:
    rows = list(entries)
    if output_format == "json":
        clean = [{k: v for k, v in row.items() if not k.startswith("_")} for row in rows]
        return json.dumps(clean, indent=2, ensure_ascii=False)
    if output_format == "csv":
        out = io.StringIO()
        fieldnames = ["timestamp", "level", "operation", "status", "message", "serial"]
        writer = csv.DictWriter(out, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            meta = row.get("metadata") or {}
            writer.writerow({
                "timestamp": row.get("timestamp", ""),
                "level": row.get("level", ""),
                "operation": row.get("operation", ""),
                "status": row.get("status", ""),
                "message": row.get("message", ""),
                "serial": meta.get("serial", ""),
            })
        return out.getvalue().rstrip("\n")
    headers = ["timestamp", "level", "operation", "status", "serial", "message"]
    data = []
    for row in rows:
        if "_parse_error" in row:
            data.append([f"line {row['_line']}", "ERROR", "parse", "failure", "", row["_parse_error"]])
        else:
            meta = row.get("metadata") or {}
            data.append([
                row.get("timestamp", ""),
                row.get("level", ""),
                row.get("operation", ""),
                row.get("status", ""),
                meta.get("serial", ""),
                row.get("message", ""),
            ])
    if not data:
        return "No audit entries found."
    widths = [len(h) for h in headers]
    for row in data:
        for i, value in enumerate(row):
            widths[i] = min(max(widths[i], len(str(value))), 60)
    def cell(value, i):
        text = str(value)
        if len(text) > widths[i]:
            text = text[:widths[i]-1] + "…"
        return text.ljust(widths[i])
    line = "  ".join(cell(h, i) for i, h in enumerate(headers))
    sep = "  ".join("-" * widths[i] for i in range(len(headers)))
    body = ["  ".join(cell(value, i) for i, value in enumerate(row)) for row in data]
    return "\n".join([line, sep] + body)


def main_verify_cli(log_file: str, chain_file: str | None = None) -> int:
    ok, msg, _ = verify_log(log_file, chain_file)
    print(msg, file=sys.stdout if ok else sys.stderr)
    return 0 if ok else 2
