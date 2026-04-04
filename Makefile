.PHONY:	clean_dist dist test validate format apidoc html doc browse publish_test

clean_dist:
	rm -rf dist/*
	rm -rf src/pipcanary.egg-info

dist:
	rm -rf dist/*
	python -m build
	rm -rf src/pipcanary.egg-info

format:
	black src tests ecilpack

validate:
	pyright src tests
	ruff check src tests

test:
	python -m unittest discover -v -s tests/unit -p '*_test.py'
