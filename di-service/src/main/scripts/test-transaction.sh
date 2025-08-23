#!/usr/bin/env bash
# This will test the DBService on localhost. Set the DATA elements for the key/value pairs
# Note that this is very, very specific to my system. If you need something like it, you
# will have to edit the file.
DBSERVICE='https://localhost:9443/oauth2/dbService'
DATA=('action=createTransaction')
DATA+=('client_id=myproxy:oa4mp,2012:/client_id/2d64db86be09eecd4a55e3b410a9096b')
DATA+=('scope= openid email profile')
DATA+=('oidc=135982')
DATA+=('response_type=code')
DATA+=('redirect_uri=https://localhost:9443/client2/ready')
DATA+=('us_idp=1')
CURL="curl -s -G -k"
for i in "${DATA[@]}" ; do
    CURL+=" --data-urlencode '$i'"
done
CURL+=" '$DBSERVICE'"
echo $CURL
# eval $CURL | while read; do : "${REPLY//%/\\x}"; echo -e ${_//+/ }; done
eval $CURL