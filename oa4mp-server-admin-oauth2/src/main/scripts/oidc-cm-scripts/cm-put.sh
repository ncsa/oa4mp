# A script that performs a cURL call to an OA4MP server that has the client management API enabled on it.
# This performs a HTTP PUT to the registration endpoint, updating all values for the client.
# Note that any values missing will be deleted from the information for the server!
# You MUST register and have approved an admin client for this to work.  This script sets all the headers and such
# you need to do and monitors the response.
#

# E.g.
# Issue this with a json object that contains the updates plus all the information for the client you want to
# keep. Note that the REGISTRATION_URI (which typically has the client id as a parameter) has to be set.
#
# ./cm-put.sh update.json
#
# response is a JSON object updated information, echo-ed to the console. The minimum json must contain the
# client_name and some redirect_uri entries. If you use the minimum, you will get a minimal client,
# e.g. the only scope will be openid, if the server supports OIDC.


source ./cm-setenv.sh

curl -k -X PUT -H "Authorization: Bearer $(echo -n $ADMIN_ID:$ADMIN_SECRET | base64)" -H "Content-Type: application/json; charset=UTF-8" --data @$1 $REGISTRATION_URI > output.json
cat output.json


