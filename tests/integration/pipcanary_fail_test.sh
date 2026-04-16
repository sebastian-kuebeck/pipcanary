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
    Werkzeug<=3.1.7
    flask
    pip<26.0.0
END

set +e

export PYTHONPATH=./src

python -m pipcanary -r $REQUIREMENTS_FILE 
rc=$?