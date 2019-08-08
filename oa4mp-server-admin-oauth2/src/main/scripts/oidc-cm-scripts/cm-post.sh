#!/bin/bash
# A script that performs a cURL call to an OA4MP server that has the client management API enabled on it.
# This will issue a POST to the endpoint (as per RFC 7591) and will create a new client on the server
# from the given JSON object.
# You MUST register and have approved an admin client for this to work.  This script sets all the headers and such
# you need to do and monitors the response. Note that the admin client is created out of band. The regular client
# that is created will be automatically approved and should work immediately after this call succeeds.
#
# E.g.
# ./cm-post.sh create.json
#
# response is a JSON object with the id, secret a registration endpoint for future operations on this client,
# and perhaps other information relating to the server's management (such as when the id was issued or perhaps
# when it expires).

source ./cm-setenv.sh

curl -k -X POST -H "Authorization: Bearer $(echo -n $ADMIN_ID:$ADMIN_SECRET | base64)" -H "Content-Type: application/json; charset=UTF-8" --data @$1 $SERVER > output.json
cat output.json


