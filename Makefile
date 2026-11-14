PY ?= python3

.PONY: install test lint compile replay live verify fixtures ablate demo

install:
	$(PY) -m pip install -e ".[dev]"

test: lint
	$(PY) -m pytest tests/ -q

lint:
	$(PY) -m ruff check src tests tools

compile:
	$(PY) -m sigdiff compile

replay:
	$(PY) -m sigdiff replay

live:
	SIGDIFF_SUDO_PW='$(PW)' $(PY) -m sigdiff run --out run.yaml

fixtures:
	$(PY) -m sigdiff publish-fixtures --run run.yaml --out fixtures

verify:
	SIGDIFF_SUDO_PW='$(PW)' $(PY) -m sigdiff verify --baseline run.yaml

ablate:
	$(PY) -m sigdiff ablate --rules-a rules --rules-b rules-b

# full DoD sequence: live capture -> fixtures -> offline replay -> ablation
demo: live fixtures replay ablate
