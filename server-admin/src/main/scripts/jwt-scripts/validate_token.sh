#!/bin/bash
# Validate a token. This prints out nothing. It merely returns a 0 if the token has a valid signature and
# a 1 otherwise. If you invoke it with the -v (verbose) flag, it will print out a message to that effect too.

# If you need help invoke this script with an argument of --help.
# See set-env.sh in this directory

source ./set-env.sh

if [ -z "$JWT_JAR" ]; then
  JWT_JAR=jwt.jar
fi

java -jar $JWT_JAR validate_token -log $JWT_LOG -batch  "$@"

if [ $? != 0 ]; then
  exit 1
fi

exit 0