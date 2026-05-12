.PHONY: test lint format-check type coverage security mutation-smoke fuzz-smoke check

test:
	python -m unittest discover -s tests

lint:
	ruff check .

format-check:
	ruff format --check .

type:
	mypy src

coverage:
	coverage run -m unittest discover -s tests
	coverage report --fail-under=83

security:
	bandit -r src

mutation-smoke:
	python scripts/mutation_smoke.py

fuzz-smoke:
	PYTHONPATH=src python scripts/fuzz_smoke.py

check:
	ruff check .
	ruff format --check .
	mypy src
	coverage run -m unittest discover -s tests
	coverage report --fail-under=83
	bandit -r src
