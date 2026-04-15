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
    click<=8.3.1
    flask
END

set +e

export PYTHONPATH=./src
# python -m pipcanary -r $REQUIREMENTS_FILE -i http://localhost:3141/root/pypi/+simple/ --uploaded-prior-to 2026-04-01T00:00:00+00:00
python -m pipcanary -r $REQUIREMENTS_FILE 
rc=$?