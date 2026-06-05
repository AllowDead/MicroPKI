"""Cross-platform normal test runner for MicroPKI.

The 1000-certificate performance test is excluded from normal runs. Use
`make perf-test` or `MICROPKI_RUN_PERF=1 python -m pytest -q -m perf` for it.
"""
import subprocess
import sys


def main() -> int:
    return subprocess.call([sys.executable, "-m", "pytest", "-v", "-k", "not perf"])


if __name__ == "__main__":
    raise SystemExit(main())
