#!/bin/bash
# Create and sign a token with the given key. This simply encodes a given file, no claims such as expiration times
# are added. If you need those, use generate_token.sh instead.
# If you need help invoke this script with an argument of --help.
# See set-env.sh in this directory


if [ -z "$JWT_JAR" ]; then
  JWT_JAR=jwt.jar
fi

java -jar $JWT_JAR create_token -log $JWT_LOG -batch  "$@"

if [ $? != 0 ]; then
  exit 1
fi

exit 0