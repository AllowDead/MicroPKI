"""Cross-platform test runner for MicroPKI.

Usage:
    python run_tests.py
"""
import subprocess
import sys


def main() -> int:
    return subprocess.call([sys.executable, "-m", "pytest", "-q"])


if __name__ == "__main__":
    raise SystemExit(main())
