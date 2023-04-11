# A script that performs a cURL call to an OA4MP server that has the client management API enabled on it.
# This will delete a given client from the server. This happens in real time and is immediate.
# You MUST register and have approved an admin client for this to work.  This script sets all the headers and such
# you need to do and monitors the response.
#

# E.g.
# ./cm-delete.sh
#
# A successful response has no body and is a HTTP "no content" code of 204.

source ./cm-setenv.sh

curl -k -X DELETE -H "Authorization: Bearer $BEARER_TOKEN"  $REGISTRATION_URI > output.json
cat output.json


