# A script that performs a cURL call to an OA4MP server that has the client management API enabled on it.
# This script will issue a GET to then endpoint and the response will be a JSON object containing
# the properties for the client.
# You MUST register and have approved an admin client for this to work.  This script sets all the headers and such
# you need to do and monitors the response.
# An empty REGISTRATION_URI will result in retrieving all the clients created by the admin client.
#
# E.g.
# ./cm-get.sh create.json
#
# response is a JSON object, echo-ed to the command line and stored in the local file output.json.

source ./cm-setenv.sh

curl -k -X GET -H "Authorization: Bearer $BEARER_TOKEN"  $REGISTRATION_URI> output.json
cat output.json


