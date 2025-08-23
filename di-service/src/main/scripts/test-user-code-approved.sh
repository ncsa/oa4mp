#!/usr/bin/env bash
# This will test the DBService call userCodeApproved on localhost.
# test-user_code_approved user_code is_approved
# user_code = the user code from the device flow
# is_approved = 0 (cancel) or 1 (approve)

# example of what this calls
# curl -s -G -k --data-urlencode 'action=userCodeApproved' --data-urlencode 'user_code=KL5-VNP-5J5' --data-urlencode 'approved=1' 'https://localhost:9443/oauth2/dbService'


if [[  "$1" = "--help"  ]];then
  echo "userCodeApproved user_code is_approved"
  echo "user_code - from the device flow for the service."
  echo "is_approved = 0 (cancel) or 1 (approve)"
  echo "Call the local DB service with the given user_code and is_approved."
  echo "This will return whether or not the user_code is valid and if so, "
  echo "cancel or approve it as requested."
  exit 1
fi


#DBSERVICE='http://localhost:8080/oauth2/dbService'
# On my system:
DBSERVICE='https://localhost:9443/oauth2/dbService'
DATA=('action=userCodeApproved')
DATA+=("user_code=$1")
DATA+=("approved=$2")

CURL="curl -s -G -k "
for i in "${DATA[@]}" ; do
    CURL+=" --data-urlencode '$i'"
done
CURL+=" '$DBSERVICE'"
echo $CURL
eval $CURL | while read; do : "${REPLY//%/\\x}"; echo -e ${_//+/ }; done