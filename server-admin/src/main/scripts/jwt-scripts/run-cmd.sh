#!/bin/bash
# Run a command. Note that this just passes along the arguments so any command can be run.

source ./set-env.sh

if [[ $1 == "--help" ]];then
  echo "See the readme.txt file in this directory."
  exit 1
fi

if [ -z "$JWT_JAR" ]; then
  JWT_JAR=jwt.jar
fi

java -jar $JWT_JAR  -log $JWT_LOG -run  "$@"

if [ $? != 0 ]; then
  exit 1
fi

exit 0

