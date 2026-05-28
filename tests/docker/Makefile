.PHONY: dist build run

dist:
	rm -f pipcanary-*.whl
	cd ../.. && python -m build
	rm -r ../../src/pipcanary.egg-info
	cp ../../dist/pipcanary-*-py3-none-any.whl .

build: dist
	docker build --build-arg WHEEL=`ls pipcanary-*-py3-none-any.whl` -t pipcanary-docker-test .
	rm pipcanary-*-py3-none-any.whl

run:
	mkdir -p shared
	rm -rf shared/*
	cp ../../pyproject.toml shared/
	docker run -v "$(PWD)/shared:/var/shared" --privileged pipcanary-docker-test
