.PHONY: lint fmt install install-dev install-all test tags build clean help docs publish init
.DEFAULT_GOAL := help

VENV?=.venv
PIP=$(VENV)/bin/pip
PY=$(VENV)/bin/python
VENV_ACTIVATE=. $(VENV)/bin/activate

lint: ## lint the source code
	$(VENV_ACTIVATE) && ruff check src/ tests/
	$(VENV_ACTIVATE) && ruff format --check --exclude "src/*/_version.py" src/ tests/

fmt: ## format the source code with ruff
	$(VENV_ACTIVATE) && ruff format src/ tests/
	$(VENV_ACTIVATE) && ruff check --fix src/ tests/

install: ## install into current env
	$(PIP) install '.'

install-dev: ## install with dev dependencies and with editable flag
	$(PIP) install -e '.[dev]'

test: ## run tests
	$(VENV_ACTIVATE) && pytest tests/

tags: ## build a ctags file for my editor
	ctags --languages=python -f tags -R src tests

build: clean ## build the package
	python -m build

clean: ## clean build artifacts and __pycache__ files up
	rm -rf dist/ build/ *.egg-info src/*.egg-info docs/_build
	find . -type f -name '*.py[co]' -delete -o -type d -name __pycache__ -delete
	# (optional) cd docs && $(MAKE) clean

help: ## this help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9._-]+:.*?## / {printf "\033[1m\033[36m%-38s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

init: $(VENV)/init

$(VENV)/init: ## init the virtual environment
	python3 -m venv $(VENV)
	touch $@

docs:
	cd docs && $(MAKE) html

dist: clean build ## build the package distribution using twine
	$(PY) -m twine check dist/*

check-dist:
	. $(VENV)/bin/activate && check-manifest --ignore src/jwbmisc/_version.py
	. $(VENV)/bin/activate && check-wheel-contents
	. $(VENV)/bin/activate && pyroma .

publish: dist ## publish the package to pypi
	$(PY) -m twine upload dist/*
