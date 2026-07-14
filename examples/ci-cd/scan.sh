#!/bin/bash

set -e

export PATH="$VIRTUAL_ENV/bin:$PATH"
cutoff="$(date -u -d '7 days ago' +'%Y-%m-%dT%H:%M:%SZ')"

#
# Generates an SBOM from the docker image
# see: https://siemens.github.io/debsbom/index.html
#
debsbom --progress generate -t cdx -o /var/shared/docker-image.sbom.cdx.json

#
# Scans requirements file and generates a "locked" version with hashes
#
pipcanary -p /var/shared/pyproject.toml -l /var/shared/requirements-locked.txt --pip-args="--uploaded-prior-to=$cutoff"

#
# Generates an SBOM from the locked version requirements file
# see: https://cyclonedx.org/
#
cyclonedx-py requirements /var/shared/requirements-locked.txt > /var/shared/requirements-locked.sbom.cdx.json
