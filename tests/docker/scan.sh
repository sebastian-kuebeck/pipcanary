#!/bin/bash

set -e

export PATH="$VIRTUAL_ENV/bin:$PATH"

pipcanary -p /var/shared/pyproject.toml -l /var/shared/requirements-locked.txt
cyclonedx-py requirements /var/shared/requirements-locked.txt > /var/shared/requirements-locked.cdx.json
