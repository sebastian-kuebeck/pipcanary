#!/bin/bash

set -e

export PATH="$VIRTUAL_ENV/bin:$PATH"

#
# Scans requirements file and generates a "locked" version with hashes
#
pipcanary -p /var/shared/pyproject.toml -l /var/shared/requirements-locked.txt --allow-upload-time='urllib3<=2026-05-07T16:13:18'

#
# Generates an SBOM from the locked version requirements file
# see: https://cyclonedx.org/
#
cyclonedx-py requirements /var/shared/requirements-locked.txt > /var/shared/requirements-locked.cdx.json
