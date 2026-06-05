@echo off
python -m pytest -v -k "not perf"
