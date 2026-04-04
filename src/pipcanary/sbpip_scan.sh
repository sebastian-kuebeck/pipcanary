#!/bin/sh
set -e

REQUIREMENTS_FILE=${REQUIREMENTS_FILE:-requirements.txt}
PYTHON3=`which python`

PYTHON_BIN="$(dirname $PYTHON3)"
PYTHON_DIR="$(dirname $PYTHON_BIN)"

echo "Unsing python directory $PYTHON_DIR..."

VIRTUAL_ENV=${PIPCANARY_VIRTUAL_ENV:-`mktemp -d --suffix=-pipcanary`}

echo "Creating virtual environment in $VIRTUAL_ENV..."

mkdir -p $VIRTUAL_ENV
chmod -R a+rw $VIRTUAL_ENV
rm -rf $VIRTUAL_ENV/* 
$PYTHON3 -m venv $VIRTUAL_ENV

echo "Installing $REQUIREMENTS_FILE..."
cp -v $REQUIREMENTS_FILE $VIRTUAL_ENV/requirements.txt
chmod -R a+r $VIRTUAL_ENV/requirements.txt

strace -f -e trace=file \
bwrap \
  --unshare-user \
  --share-net \
  --die-with-parent \
  --uid 0 --gid 0 \
  --new-session \
  --bind $PYTHON_DIR $PYTHON_DIR \
  --bind $VIRTUAL_ENV $VIRTUAL_ENV \
  --proc /proc \
  --dev /dev \
  --ro-bind /usr /usr \
  --ro-bind /lib /lib \
  --ro-bind /lib64 /lib64 \
  --ro-bind /etc/ssl/certs/ /etc/ssl/certs/ \
  --ro-bind /etc/resolv.conf /etc/resolv.conf \
  --clearenv \
  --setenv HOME "/root" \
  --setenv PATH "$VIRTUAL_ENV/bin:/usr/bin" \
  --chdir $VIRTUAL_ENV \
  sh -c "pip install --no-cache -r requirements.txt; pip list --format=json > packages.json"

if [ -z "${PIPCANARY_VIRTUAL_ENV+x}" ]; then
  echo "Removing $VIRTUAL_ENV..."
  rm -r $VIRTUAL_ENV
fi

echo "Done."