.DEFAULT_GOAL := help
PY := .venv/bin/python
BIN := .venv/bin

.PHONY: help
help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

.PHONY: setup
setup:  ## Create .venv and install the package with all dev dependency groups
	python3 -m venv .venv
	$(BIN)/pip install --upgrade pip
	$(BIN)/pip install -e . --group dev

.PHONY: format
format:  ## Apply formatting and autofixable lint rules
	$(BIN)/ruff format .
	$(BIN)/ruff check --fix .

.PHONY: lint
lint:  ## Check formatting, lint, and the class-based design
	$(BIN)/ruff format --check .
	$(BIN)/ruff check .
	$(PY) scripts/check_class_design.py
	$(PY) scripts/check_reachability.py

.PHONY: types
types:  ## Type check (strict)
	$(BIN)/mypy

.PHONY: arch
arch:  ## Enforce the L0-L4 layer contracts
	$(BIN)/lint-imports --verbose

.PHONY: test
test:  ## Fast test loop (excludes concurrency and slow tests)
	$(BIN)/pytest -m "not concurrency and not slow" -n auto

.PHONY: test-all
test-all:  ## Full suite with coverage, concurrency tests run serially
	$(BIN)/pytest -m "not concurrency and not failure_injection" --cov=attest --cov-report= -n auto
	@# Exit code 5 means "no tests collected". That is currently TRUE and is a gap,
	@# not a success: red-team families 5, 7 and 10 need concurrency and fault
	@# injection, and none of it exists yet. Tolerated so the gate is runnable, and
	@# announced loudly so it cannot be mistaken for coverage.
	@$(BIN)/pytest -m "concurrency or failure_injection" --cov=attest --cov-append --cov-report=; \
	rc=$$?; \
	if [ $$rc -eq 5 ]; then \
		echo ""; \
		echo "  !! NO concurrency or failure-injection tests exist yet."; \
		echo "     Grant redemption races, budget reservation races and crash-"; \
		echo "     between-submit-and-commit are UNTESTED. See docs/assurance/redteam.md."; \
		echo ""; \
	elif [ $$rc -ne 0 ]; then exit $$rc; fi
	$(BIN)/coverage combine || true
	$(BIN)/coverage report

.PHONY: security
security:  ## Adversarial suite, static analysis and dependency audit
	$(BIN)/pytest -m security -v
	$(BIN)/bandit -r src/attest -c pyproject.toml
	@# --skip-editable omits attest itself, which is an unpublished local install and
	@# cannot be looked up. --strict is deliberately NOT set: its only effect is to
	@# make that skip fatal, which would fail the gate on our own absence from PyPI
	@# rather than on a vulnerability. Every third-party dependency is still audited.
	$(BIN)/pip-audit --desc --skip-editable

.PHONY: build
build:  ## Build sdist and wheel reproducibly
	$(BIN)/pip install --quiet build twine
	SOURCE_DATE_EPOCH=1700000000 $(PY) -m build
	$(BIN)/twine check --strict dist/*

.PHONY: install-check
install-check: build  ## Verify a clean-environment install pulls only the declared runtime deps
	rm -rf /tmp/attest-clean
	python3 -m venv /tmp/attest-clean
	/tmp/attest-clean/bin/pip install --quiet dist/*.whl
	cd /tmp && /tmp/attest-clean/bin/python -c "import attest; print(attest.__version__)"
	@extra=$$(/tmp/attest-clean/bin/pip list --format=freeze \
		| grep -viE '^(pip|setuptools|wheel|attest-control-plane|asn1crypto|cryptography|cffi|pycparser)=' || true); \
	if [ -n "$$extra" ]; then echo "Base install pulled undeclared dependencies:"; echo "$$extra"; exit 1; fi; \
	echo "Base install pulls only asn1crypto and cryptography, as declared."

.PHONY: docs
docs:  ## Check documentation consistency and build the site
	$(PY) scripts/check_docs_consistency.py
	$(BIN)/mkdocs build --strict

.PHONY: check
check: lint types arch test-all security build install-check docs  ## Everything CI runs

.PHONY: clean
clean:  ## Remove build and cache artefacts
	rm -rf build dist .coverage .coverage.* coverage.xml htmlcov \
		.pytest_cache .mypy_cache .ruff_cache .hypothesis site
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
