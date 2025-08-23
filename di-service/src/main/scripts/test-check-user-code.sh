#!/usr/bin/env bash
# This will test the DBService call checkUserCode on localhost.
# test-check-user-code user_code
# user_code - what is returned from the service

# Example of what this calls:
# curl -s -G -k --data-urlencode 'action=checkUserCode' --data-urlencode 'user_code=HPS-TG5-GC2' 'https://localhost:9443/oauth2/dbService'

if [[  "$1" = "--help"  ]];then
  echo "checkUserCode user_code"
  echo "user_code - from the device flow for the service."
  echo "Call the local DB service with the given user_code."
  echo "This will query the service on the user user_code, returning"
  echo "various bits of information."
  exit 1
fi


# DBSERVICE='http://localhost:8080/oauth2/dbService'
# On my system
#DBSERVICE='https://localhost:9443/oauth2/dbService'
DBSERVICE='http://localhost:44444/oauth2/dbService'
DATA=('action=checkUserCode')
DATA+=("user_code=$1")

CURL="curl -s -G -k "
for i in "${DATA[@]}" ; do
    CURL+=" --data-urlencode '$i'"
done
CURL+=" '$DBSERVICE'"
echo $CURL
eval $CURL | while read; do : "${REPLY//%/\\x}"; echo -e ${_//+/ }; done
