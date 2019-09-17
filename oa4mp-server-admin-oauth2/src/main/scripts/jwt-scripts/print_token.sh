#!/bin/bash
# Print a token. No validation is done, the token is decoded and the header and payload are printed.
# If you need help invoke this script with an argument of --help.
# See set-env.sh in this directory

if [ -z "$JWT_JAR" ]; then
  JWT_JAR=jwt.jar
fi

java -jar $JWT_JAR -batch print_token $1

if [ $? != 0 ]; then
  exit 1
fi

exit 0