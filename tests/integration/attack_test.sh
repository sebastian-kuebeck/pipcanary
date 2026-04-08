#!/bin/sh

set -e

cd evilpack && python -m build
cd ..

WHEEL_PATH=$PWD/evilpack/dist

REQUIREMENTS_FILE=`mktemp`

rc=0

cleanup() {
  rm $REQUIREMENTS_FILE
  exit $rc
}

trap cleanup EXIT

cat << END > $REQUIREMENTS_FILE 
    $WHEEL_PATH/evilpack-0.1.0-py3-none-any.whl
END

set +e

export PYTHONPATH=./src
python -m pipcanary -r $REQUIREMENTS_FILE --additional-directory=$WHEEL_PATH --trace-file strace.out
rc=$?