.PHONY: test test-verbose coverage perf-test demo

test:
	python -m pytest -q -k "not perf"

test-verbose:
	python -m pytest tests/ -v -k "not perf"

coverage:
	python -m pytest -q -k "not perf" --cov=micropki --cov-report=term-missing

perf-test:
	MICROPKI_RUN_PERF=1 python -m pytest -q -m perf

demo:
	python demo/demo.py
