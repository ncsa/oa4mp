# A script that performs a cURL call to an OA4MP server that has the client management API enabled on it.
# You MUST register and have approved an admin client for this to work.  This script sets all the headers and such
# you need to do and monitors the response.
#
# HOW THIS WORKS
#
# You need to set the following variables:
# SERVER = the address of the server that has the client management service on it
# ADMIN_ID = the identifer for the admin client
# ADMIN_SECRET = the secret for this client. If it has embedded blanks, put it in double quotes
#
# Once you have an admin client id and its secret, you may set them here as variables. Make sure this is set to being
# executable. You must also set the server
# This script requires an argument in the form of a JSON object that has the right key/value pairs as per the spec.
# (A sample called create.json is included.) When you run the from the command line, a single file is created:
# output.json the response from the server.
# This is printed out after this script is run, so you get to see the output at the command
# line.
# E.g.
# ./cm-run.sh create.json
#
# response is a JSON object with the id and secret.

export SERVER=https://polod.ncsa.illinois.edu/oauth2/oidc-cm
export ADMIN_ID=put-your-id-here
export ADMIN_SECRET=put-your-secret-here

curl -k -X POST -H "Authorization: Bearer $(echo -n $ADMIN_ID:$ADMIN_SECRET | base64)" -H "Content-Type: application/json; charset=UTF-8" --data @$1 $SERVER > output.json
cat output.json


