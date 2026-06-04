.PHONY: test test-verbose

test:
	python -m pytest -q

test-verbose:
	python -m pytest tests/ -v
