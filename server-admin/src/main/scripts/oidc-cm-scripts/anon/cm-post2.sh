#!/bin/bash
# A script that performs a cURL call to an OA4MP server that has the client management API enabled on it.
# This will issue a POST to the endpoint (as per RFC 7591) and will create a new client on the server
# from the given JSON object.
# Note that is for the case where anonymous requests to this service are allowed.
# No admin client is needed and server policies (typically that the client is not
# approved until vetted by the system administrator) or in effect. This is no different
# than going to the registration endpoint for the server and filling out the form.
# E.g.
# ./cm-post2.sh create.json
#
# response is a standard compliant JSON object with the id, secret a registration endpoint for future operations on this client,
# and perhaps other information relating to the server's management (such as when the id was issued or perhaps
# when it expires).
# OA4MP does nto alloow clients to update or delete themselves.

source ./cm-setenv2.sh


curl -k -X POST  -H "Content-Type: application/json; charset=UTF-8" --data @$1 $SERVER > output.json
cat output.json


