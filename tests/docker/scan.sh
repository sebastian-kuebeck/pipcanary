#!/bin/bash

set -e

export PATH="$VIRTUAL_ENV/bin:$PATH"

cutoff="$(date -u -d '7 days ago' +'%Y-%m-%dT%H:%M:%SZ')"

debsbom --progress generate -t cdx -o /var/shared/docker-image.sbom.cdx.json
pipcanary -p /var/shared/pyproject.toml -l /var/shared/requirements-locked.txt --log-level=DEBUG --pip-args="--uploaded-prior-to=$cutoff"
cyclonedx-py requirements /var/shared/requirements-locked.txt > /var/shared/requirements-locked.sbom.cdx.json
