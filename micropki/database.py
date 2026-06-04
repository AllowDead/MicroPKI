"""SQLite persistence layer for MicroPKI certificate metadata."""

from __future__ import annotations

import contextlib
import csv
import datetime as _dt
import io
import json
import os
import re
import sqlite3
from dataclasses import dataclass
from typing import Iterable, Iterator, Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .crypto_utils import name_to_string

SCHEMA_VERSION = 1
VALID_STATUSES = {"valid", "revoked", "expired"}
_SERIAL_RE = re.compile(r"^[0-9A-Fa-f]+$")


@dataclass(frozen=True)
class CertificateRecord:
    serial_hex: str
    subject: str
    issuer: str
    not_before: str
    not_after: str
    cert_pem: str
    status: str = "valid"
    revocation_reason: Optional[str] = None
    revocation_date: Optional[str] = None
    created_at: Optional[str] = None


def utc_now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def cert_time_to_iso(value: _dt.datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=_dt.timezone.utc)
    return value.astimezone(_dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def normalize_serial_hex(serial: str | int) -> str:
    if isinstance(serial, int):
        if serial <= 0:
            raise ValueError("Serial number must be positive")
        return f"{serial:X}"
    value = str(serial).strip()
    if value.lower().startswith("0x"):
        value = value[2:]
    value = value.strip().upper()
    if not value or not _SERIAL_RE.fullmatch(value):
        raise ValueError("Serial must be a non-empty hexadecimal string")
    return value.lstrip("0") or "0"


def _connect(db_path: str) -> sqlite3.Connection:
    db_path = os.path.abspath(db_path)
    parent = os.path.dirname(db_path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextlib.contextmanager
def _connection(db_path: str) -> Iterator[sqlite3.Connection]:
    """Open a SQLite connection, commit/rollback transactions, and always close it.

    The sqlite3.Connection context manager does not close the file handle on
    Windows; it only commits or rolls back. This wrapper prevents locked
    temporary database files during tests and CLI runs.
    """
    with contextlib.closing(_connect(db_path)) as conn:
        with conn:
            yield conn


def init_database(db_path: str = "./pki/micropki.db") -> str:
    """Create the Sprint 3 SQLite schema. Idempotent."""
    db_path = os.path.abspath(db_path)
    with _connection(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS certificates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                serial_hex TEXT UNIQUE NOT NULL,
                subject TEXT NOT NULL,
                issuer TEXT NOT NULL,
                not_before TEXT NOT NULL,
                not_after TEXT NOT NULL,
                cert_pem TEXT NOT NULL,
                status TEXT NOT NULL,
                revocation_reason TEXT,
                revocation_date TEXT,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_certificates_serial_hex ON certificates(serial_hex)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_certificates_status ON certificates(status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_certificates_issuer ON certificates(issuer)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_certificates_not_after ON certificates(not_after)")
        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (?, ?)",
            (SCHEMA_VERSION, utc_now_iso()),
        )
    return db_path


def serial_exists(db_path: str, serial: str | int) -> bool:
    serial_hex = normalize_serial_hex(serial)
    init_database(db_path)
    with _connection(db_path) as conn:
        row = conn.execute(
            "SELECT 1 FROM certificates WHERE UPPER(serial_hex) = ? LIMIT 1",
            (serial_hex,),
        ).fetchone()
    return row is not None


def certificate_to_record(cert: x509.Certificate, status: str = "valid") -> CertificateRecord:
    if status not in VALID_STATUSES:
        raise ValueError(f"Unsupported certificate status: {status}")
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    return CertificateRecord(
        serial_hex=normalize_serial_hex(cert.serial_number),
        subject=name_to_string(cert.subject),
        issuer=name_to_string(cert.issuer),
        not_before=cert_time_to_iso(cert.not_valid_before_utc),
        not_after=cert_time_to_iso(cert.not_valid_after_utc),
        cert_pem=cert_pem,
        status=status,
        created_at=utc_now_iso(),
    )


def insert_certificate(conn: sqlite3.Connection, record: CertificateRecord) -> None:
    conn.execute(
        """
        INSERT INTO certificates (
            serial_hex, subject, issuer, not_before, not_after, cert_pem,
            status, revocation_reason, revocation_date, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            normalize_serial_hex(record.serial_hex),
            record.subject,
            record.issuer,
            record.not_before,
            record.not_after,
            record.cert_pem,
            record.status,
            record.revocation_reason,
            record.revocation_date,
            record.created_at or utc_now_iso(),
        ),
    )


def insert_certificate_record(db_path: str, record: CertificateRecord) -> None:
    """Insert one certificate record using a short-lived managed connection.

    This helper is intentionally used by tests and CLI-style workflows that do
    not need to keep a transaction open. It avoids raw sqlite3.connect calls,
    which can leave locked database files on Windows if a test exits before all
    cursors are finalized.
    """
    init_database(db_path)
    with _connection(db_path) as conn:
        insert_certificate(conn, record)


def schema_is_initialized(db_path: str) -> bool:
    """Return True when the Sprint 3 schema and expected index exist."""
    init_database(db_path)
    with _connection(db_path) as conn:
        table = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='certificates'"
        ).fetchone()
        idx = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND name='idx_certificates_serial_hex'"
        ).fetchone()
    return table is not None and idx is not None


@contextlib.contextmanager
def certificate_insertion_transaction(db_path: str, record: CertificateRecord) -> Iterator[sqlite3.Connection]:
    """Insert a certificate first, then let caller write files before committing.

    If DB insertion fails, the caller never reaches file writing. If file writing
    raises, the transaction is rolled back by this context manager.
    """
    init_database(db_path)
    conn = _connect(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        insert_certificate(conn, record)
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _row_to_dict(row: sqlite3.Row) -> dict:
    return dict(row)


def get_certificate_by_serial(db_path: str, serial_hex: str) -> Optional[dict]:
    serial_hex = normalize_serial_hex(serial_hex)
    init_database(db_path)
    with _connection(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM certificates WHERE UPPER(serial_hex) = ?",
            (serial_hex,),
        ).fetchone()
    return _row_to_dict(row) if row else None


def list_certificates(
    db_path: str,
    status: Optional[str] = None,
    issuer: Optional[str] = None,
    not_before_from: Optional[str] = None,
    not_after_to: Optional[str] = None,
) -> list[dict]:
    if status and status not in VALID_STATUSES:
        raise ValueError("status must be one of: valid, revoked, expired")
    init_database(db_path)
    where = []
    params: list[str] = []
    now = utc_now_iso()
    if status == "valid":
        where.append("status = 'valid' AND not_after >= ?")
        params.append(now)
    elif status == "expired":
        where.append("(status = 'expired' OR (status = 'valid' AND not_after < ?))")
        params.append(now)
    elif status == "revoked":
        where.append("status = 'revoked'")
    if issuer:
        where.append("issuer = ?")
        params.append(issuer)
    if not_before_from:
        where.append("not_before >= ?")
        params.append(not_before_from)
    if not_after_to:
        where.append("not_after <= ?")
        params.append(not_after_to)
    sql = "SELECT * FROM certificates"
    if where:
        sql += " WHERE " + " AND ".join(f"({w})" for w in where)
    sql += " ORDER BY created_at, id"
    with _connection(db_path) as conn:
        rows = conn.execute(sql, params).fetchall()
    return [_row_to_dict(row) for row in rows]


def update_certificate_status(
    db_path: str,
    serial_hex: str,
    status: str,
    revocation_reason: Optional[str] = None,
    revocation_date: Optional[str] = None,
) -> bool:
    if status not in VALID_STATUSES:
        raise ValueError("status must be one of: valid, revoked, expired")
    serial_hex = normalize_serial_hex(serial_hex)
    if status == "revoked" and revocation_date is None:
        revocation_date = utc_now_iso()
    init_database(db_path)
    with _connection(db_path) as conn:
        cur = conn.execute(
            """
            UPDATE certificates
               SET status = ?, revocation_reason = ?, revocation_date = ?
             WHERE UPPER(serial_hex) = ?
            """,
            (status, revocation_reason, revocation_date, serial_hex),
        )
        return cur.rowcount > 0


def list_revoked_certificates(db_path: str) -> list[dict]:
    return list_certificates(db_path, status="revoked")


def format_records_table(records: Iterable[dict]) -> str:
    rows = list(records)
    headers = ["serial", "subject", "expiration", "status"]
    data = [
        [row["serial_hex"], row["subject"], row["not_after"], row["status"]]
        for row in rows
    ]
    widths = [len(h) for h in headers]
    for row in data:
        for idx, value in enumerate(row):
            widths[idx] = max(widths[idx], len(str(value)))
    line = "  ".join(headers[idx].ljust(widths[idx]) for idx in range(len(headers)))
    sep = "  ".join("-" * widths[idx] for idx in range(len(headers)))
    body = ["  ".join(str(row[idx]).ljust(widths[idx]) for idx in range(len(headers))) for row in data]
    return "\n".join([line, sep] + body) if rows else "No certificates found."


def format_records(records: Iterable[dict], output_format: str) -> str:
    rows = list(records)
    if output_format == "table":
        return format_records_table(rows)
    if output_format == "json":
        return json.dumps(rows, indent=2, ensure_ascii=False)
    if output_format == "csv":
        out = io.StringIO()
        fieldnames = [
            "serial_hex", "subject", "issuer", "not_before", "not_after", "status",
            "revocation_reason", "revocation_date", "created_at",
        ]
        writer = csv.DictWriter(out, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
        return out.getvalue().rstrip("\n")
    raise ValueError("format must be one of: table, json, csv")
