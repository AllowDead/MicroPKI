#!/usr/bin/env python3
"""Sprint 3 serial uniqueness stress helper.

Generates 100 unique serial numbers against a MicroPKI SQLite database and
prints the number of generated serials. This is a lightweight companion to the
pytest coverage for TEST-17.
"""

import argparse
import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
from micropki.database import init_database, normalize_serial_hex
from micropki.serial import generate_unique_serial


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--db-path", default="./pki/micropki.db")
    parser.add_argument("--count", type=int, default=100)
    args = parser.parse_args()
    init_database(args.db_path)
    serials = {normalize_serial_hex(generate_unique_serial(args.db_path)) for _ in range(args.count)}
    if len(serials) != args.count:
        raise SystemExit("duplicate serial generated")
    print(f"Generated {len(serials)} unique serial candidates")


if __name__ == "__main__":
    main()
