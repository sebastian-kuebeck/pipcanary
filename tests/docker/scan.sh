#!/bin/bash

set -e

export PATH="$VIRTUAL_ENV/bin:$PATH"

debsbom --progress generate -t cdx -o /var/shared/docker-image.sbom.cdx.json
pipcanary -p /var/shared/pyproject.toml -l /var/shared/requirements-locked.txt
cyclonedx-py requirements /var/shared/requirements-locked.txt > /var/shared/requirements-locked.sbom.cdx.json
