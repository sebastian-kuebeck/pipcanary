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
    pip<26.0.0
END

set +e

export PYTHONPATH=./src

python -m pipcanary -r $REQUIREMENTS_FILE --ignore-vuln ECHO-7db2-03aa-5591 --ignore-vuln GHSA-6vgw-5pg2-w6jp --ignore-vuln GHSA-4xh5-x5gv-qwph --ignore-vuln ECHO-ffe1-1d3c-d9bc
rc=$?