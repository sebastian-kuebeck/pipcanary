#!/bin/bash

set -e

#
# Scans requirements file and generates a "locked" version with hashes
#
pipcanary -r /var/shared/requirements.txt -l /var/shared/requirements-locked.txt

#
# Generates an SBOM from the locked version requirements file
# see: https://cyclonedx.org/
#
cyclonedx-py requirements /var/shared/requirements-locked.txt > /var/shared/requirements-locked.cdx.json
