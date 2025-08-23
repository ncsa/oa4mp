#!/usr/bin/env bash
# This will test the DBService on localhost. Set the DATA elements for the key/value pairs
# Note that this is very, very specific to my system. If you need something like it, you
# will have to edit the file.
# You MUST supply a valid authorization grant ('code') for this to work.
DBSERVICE='https://localhost:9443/oauth2/dbService'
DATA=('action=setTransactionState')
DATA+=('code=http://localhost:9443/oauth2/64fed8d229e84d822a764cd48d589092?type=authzGrant&ts=1752530744701&version=v2.0&lifetime=900000')
DATA+=('auth_time=1234567879')
DATA+=('loa=2')
#DATA+=('cilogon_info=info:dataOne')
# NOTE any valud userid works since this where it is set.
DATA+=('user_uid=http://cilogon.org/serverT/users/160246')
#DATA+=('us_idp=1')
CURL="curl -s -G -k"
for i in "${DATA[@]}" ; do
    CURL+=" --data-urlencode '$i'"
done
CURL+=" '$DBSERVICE'"
echo $CURL
# eval $CURL | while read; do : "${REPLY//%/\\x}"; echo -e ${_//+/ }; done
eval $CURL