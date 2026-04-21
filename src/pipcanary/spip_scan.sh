#!/bin/sh
set -e

REQUIREMENTS_FILE=${PIPCANARY_REQUIREMENTS_FILE:-requirements.txt}
PYTHON3=`which python`

PYTHON_BIN="$(dirname $PYTHON3)"
PYTHON_DIR="$(dirname $PYTHON_BIN)"

echo "Unsing python directory $PYTHON_DIR..."

VIRTUAL_ENV=${PIPCANARY_VIRTUAL_ENV:-`mktemp -d --suffix=-pipcanary`}

ADDITIONAL_DIRECTORY=${PIPCANARY_ADDITIONAL_DIRECTORY:-/usr}

echo "Creating virtual environment in $VIRTUAL_ENV..."

mkdir -p $VIRTUAL_ENV
rm -rf $VIRTUAL_ENV/* 
$PYTHON3 -m venv $VIRTUAL_ENV

echo "Installing $REQUIREMENTS_FILE..."
cp -v $REQUIREMENTS_FILE $VIRTUAL_ENV/requirements.txt

MODULE_LOADER_SOURCE=$(dirname "$0")/module_loader.py
MODULE_LOADER=$VIRTUAL_ENV/module_loader.py

SITE_PACKAGES=lib/python3.10/site-packages/

cp -v $MODULE_LOADER_SOURCE $MODULE_LOADER

# Wait for scanner
sleep 0.5

chdir $VIRTUAL_ENV
export PATH="$VIRTUAL_ENV/bin:/usr/bin"

echo "Running without bubblewrap. Stop with kill -9 $$ if it's not running in a suitable sandbox!"

pip_install="pip install --no-cache -r requirements.txt ${PIP_OPTIONS}"

echo "Starting: $pip_install..."

# Installing packages
strace -f -e trace=file \
  sh -c "$pip_install"

# Loading modules
strace -f -e trace=file \
  sh -c "python $MODULE_LOADER && pip list --format=json > packages.json"

if [ -z "${PIPCANARY_VIRTUAL_ENV+x}" ]; then
  echo "Removing $VIRTUAL_ENV..."
  rm -r $VIRTUAL_ENV
fi

echo "Scan finished."
