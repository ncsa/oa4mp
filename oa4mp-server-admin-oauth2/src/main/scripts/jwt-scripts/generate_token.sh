#!/bin/bash
# Generates a token from a set of claims. This means that time stamps and possibly a unique identifier are created
# If you need help invoke this script with an argument of --help.
# See set-env.sh in this directory

if [ -z "$JWT_JAR" ]; then
  JWT_JAR=jwt.jar
fi

java -jar $JWT_JAR generate_token -log $JWT_LOG -batch  "$@"

if [ $? != 0 ]; then
  exit 1
fi

exit 0