#!/usr/bin/env bash
# This will test the DBService on localhost. Set the DATA elements for the key/value pairs
# Note that this is very, very specific to my system. If you need something like it, you
# will have to edit the file.
DBSERVICE='https://localhost:9443/oauth2/dbService'
DATA=('action=getUser')
DATA+=('idp=http://github.com/login/oauth/authorize')
DATA+=('idp_display_name=GitHub')
DATA+=('oidc=135982')
DATA+=('us_idp=1')
CURL="curl -s -G -k "
for i in "${DATA[@]}" ; do
    CURL+=" --data-urlencode '$i'"
done
CURL+=" '$DBSERVICE'"
echo $CURL
eval $CURL | while read; do : "${REPLY//%/\\x}"; echo -e ${_//+/ }; done