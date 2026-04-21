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

cp -v $MODULE_LOADER_SOURCE $MODULE_LOADER

# Wait for scanner
sleep 0.5

pip_install="pip install --no-cache -r requirements.txt ${PIPCANARY_PIP_OPTIONS}"

echo "Running: $pip_install..."

# Installing packages with network
strace -f -e trace=file \
bwrap \
  --unshare-user \
  --share-net \
  --die-with-parent \
  --uid 0 --gid 0 \
  --new-session \
  --ro-bind $PYTHON_DIR $PYTHON_DIR \
  --bind $VIRTUAL_ENV $VIRTUAL_ENV \
  --proc /proc \
  --dev /dev \
  --ro-bind /usr /usr \
  --ro-bind /lib /lib \
  --ro-bind /lib64 /lib64 \
  --ro-bind /etc/ssl/certs/ /etc/ssl/certs/ \
  --ro-bind /etc/resolv.conf /etc/resolv.conf \
  --ro-bind $ADDITIONAL_DIRECTORY $ADDITIONAL_DIRECTORY \
  --clearenv \
  --setenv HOME "/root" \
  --setenv PATH "$VIRTUAL_ENV/bin:/usr/bin" \
  --chdir $VIRTUAL_ENV \
  bash -c "$pip_install"

# Loading modules without network and further file access restrictions
strace -f -e trace=file \
bwrap \
  --unshare-user \
  --die-with-parent \
  --uid 0 --gid 0 \
  --new-session \
  --ro-bind $PYTHON_DIR $PYTHON_DIR \
  --bind $VIRTUAL_ENV $VIRTUAL_ENV \
  --proc /proc \
  --dev /dev \
  --ro-bind /usr /usr \
  --ro-bind /lib /lib \
  --ro-bind /lib64 /lib64 \
  --clearenv \
  --setenv HOME "/root" \
  --setenv PATH "$VIRTUAL_ENV/bin:/usr/bin" \
  --chdir $VIRTUAL_ENV \
  bash -c "python $MODULE_LOADER && pip list --format=json > packages.json"

if [ -z "${PIPCANARY_VIRTUAL_ENV+x}" ]; then
  echo "Removing $VIRTUAL_ENV..."
  rm -r $VIRTUAL_ENV
fi

echo "Scan finished."
