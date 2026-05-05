#!/bin/bash

set -e

pipcanary -p /var/shared/pyproject.toml -l /var/shared/requirements-locked.txt
cyclonedx-py requirements /var/shared/requirements-locked.txt > /var/shared/requirements-locked.cdx.json
