#!/bin/bash
# Create a full set of JSON Web Key keys, along with random ids.
# If you need help invoke this script with an argument of --help.
# See set-env.sh in this directory

source ./set-env.sh

if [ -z "$JWT_JAR" ]; then
  JWT_JAR=jwt.jar
fi

java -jar $JWT_JAR create_keys -log $JWT_LOG -batch  "$@"

if [ $? != 0 ]; then
  exit 1
fi

exit 0
