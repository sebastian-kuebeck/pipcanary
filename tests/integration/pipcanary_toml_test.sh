#!/bin/sh

set -e

PROJECT_FILE=`mktemp`

rc=0

cleanup() {
  rm $PROJECT_FILE
  exit $rc
}

trap cleanup EXIT

cat << END > $PROJECT_FILE 
[project]
dependencies = [
  "virtualenv==21.2.0", 
  "tomli==2.4.1",
  "platformdirs<=4.9.4",
  "python-discovery<=1.2.1",
]
END

set +e

export PYTHONPATH=./src
python -m pipcanary -p $PROJECT_FILE
rc=$?