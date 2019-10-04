#!/bin/bash
# Run a command in batch mode. Note that this just passes along the arguments so any command can be run.

if [ -z "$JWT_JAR" ]; then
  JWT_JAR=jwt.jar
fi

java -jar $JWT_JAR  -log $JWT_LOG -batchFile  "$@"

if [ $? != 0 ]; then
  exit 1
fi

exit 0

