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
    pygments<=1.1
    flask<=3.1.2
    pip>=26.1.2
END

set +e

export PYTHONPATH=./src

python -m pipcanary -r $REQUIREMENTS_FILE
rc=$?