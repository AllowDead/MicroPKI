"""Unique serial number generator for MicroPKI certificates."""

from __future__ import annotations

import secrets
import time
from typing import Optional


def generate_candidate_serial() -> int:
    """Return a positive 64-bit composite serial.

    High 32 bits: current Unix timestamp seconds. Low 32 bits: CSPRNG value.
    This keeps at least 32 bits of randomness and gives a monotonic uniqueness
    component while remaining well within X.509 serial size limits.
    """
    high = int(time.time()) & 0xFFFFFFFF
    low = secrets.randbits(32)
    serial = (high << 32) | low
    return serial or 1


def generate_unique_serial(db_path: Optional[str] = None, max_attempts: int = 100) -> int:
    if not db_path:
        return generate_candidate_serial()
    from .database import serial_exists

    for _ in range(max_attempts):
        serial = generate_candidate_serial()
        if not serial_exists(db_path, serial):
            return serial
    raise RuntimeError("Unable to generate a unique certificate serial number")
