# DEFAULT_SERVER=https://localhost/oauth2/clients
# For debugging uncomment the next line
source ~/dev/csd/config/cm-setenv.sh
#
# Set the following:
#ADMIN_ID=
#ADMIN_SECRET=
#
# And after creating a client, set the client info here.
#
#CLIENT_ID=
#CLIENT_SECRET=

sed -e "s|CLIENT_ID|$CLIENT_ID|" -e "s|CLIENT_SECRET|$CLIENT_SECRET|" -e "s|ADMIN_ID|$ADMIN_ID|" -e "s|ADMIN_SECRET|$ADMIN_SECRET|" $1 > input.json
curl -k -X POST -H "Content-Type: application/json; charset=UTF-8" --data @input.json $SERVER > output.json
cat output.json


