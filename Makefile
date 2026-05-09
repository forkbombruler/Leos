.PHONY: test lint format-check type coverage security check

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
	coverage report --fail-under=85

security:
	bandit -r src

check:
	ruff check .
	ruff format --check .
	mypy src
	coverage run -m unittest discover -s tests
	coverage report --fail-under=85
	bandit -r src
