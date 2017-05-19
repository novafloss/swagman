.PHONY: all
all:
	@echo "Hello $(shell whoami), nothing to do by default."
	@echo "Try 'make help'."

# target: clean         Clean pyc files.
.PHONY: clean
clean:
	find ./ -name "*.pyc" -delete
	find ./ -name "__pycache__" -type d | xargs rm -rf

# target: flake8        Run flake8 check.
.PHONY: flake8
flake8:
	flake8 swagman

# target: help          Display callable targets.
.PHONY: help
help:
	@echo "Reference card for usual actions in development environment."
	@echo "Here are available targets:"
	@egrep -o "^# target: (.+)" [Mm]akefile  | sed 's/# target: / * /'

# target: install       Install in editable mode.
.PHONY: install
install:
	pip install -e .

# target: install-test  Install test requirements.
.PHONY: install-test
install-test:
	pip install -e ".[test]"

# target: release       Makes a new release.
.PHONY: release
release:
	hash fullrelease 2> /dev/null || pip install zest-releaser
	fullrelease

# target: test          Run tests.
.PHONY: test
test: clean flake8
	py.test --cov-config .coveragerc --cov-report term-missing --cov=swagman -sx -v swagman
