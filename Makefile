.PHONY:	clean_dist dist test validate format apidoc html doc browse publish_test build_evilpack

export PYTHONPATH=src:tests

clean_dist:
	rm -rf dist/*
	rm -rf src/pipcanary.egg-info
	rm -rf evilpack/evilpack.egg-info
	rm -rf evilpack/dist/*

dist:
	rm -rf dist/*
	python -m build
	rm -rf src/pipcanary.egg-info

format:
	black src tests evilpack

validate:
	pyright src tests
	ruff check src tests

audit:
	pip-audit -r requirements.txt

test:
	python -m unittest discover -v -s tests/unit -p '*_test.py'

integration_tests:
	python -m unittest discover -v -s tests/integration -p '*_test.py'

build_evilpack:
	cd evilpack && python -m build

# Install with
# 
# python -m pip install --index-url https://test.pypi.org/simple/ pipcanary
#
publish_test: dist
	twine upload -r testpypi dist/*

publish: dist
	twine upload --repository pypi dist/*

# To run tests with different environments
# 
# Prerequisites:
# - make sure you have pyenv and tox installed
# - install all python versions using 'pyenv local <versions>' specified in tox.ini
#
# see:
# -	https://github.com/pyenv/pyenv
# - https://tox.wiki
#
tox:
	tox -p