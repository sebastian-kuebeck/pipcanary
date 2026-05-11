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
    pip==26.1
END

set +e

export PYTHONPATH=./src

python -m pipcanary -r $REQUIREMENTS_FILE -c 1024
rc=$?