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
[project]
dependencies = [
  "virtualenv==21.2.0", 
  "tomli==2.4.1",
  "platformdirs<=4.9.4",
  "python-discovery<=1.2.1",
  "filelock<=3.25.2",
  "pip>=26.0.1"
]
END

set +e

export PYTHONPATH=./src
python -m pipcanary -p $REQUIREMENTS_FILE 
rc=$?