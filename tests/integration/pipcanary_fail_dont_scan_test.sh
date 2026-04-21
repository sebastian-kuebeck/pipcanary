#!/bin/sh

set -e

REQUIREMENTS_FILE=`mktemp`

rc=0

cleanup() {
  rm $REQUIREMENTS_FILE
  exit $rc
}

trap cleanup EXIT

cat << END > $REQUIREMENTS_FILE 
    Werkzeug
    pip>=26.0.1
END

set +e

export PYTHONPATH=./src

python -m pipcanary -r $REQUIREMENTS_FILE --do-not-scan Werkzeug -c 1024 --allow-upload-time='pip<=2026-02-05T02:20:18'
rc=$?
