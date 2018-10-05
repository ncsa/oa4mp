# DEFAULT_SERVER=https://locahost/oauth2/clients
# SERVER=http://localhost:44444/oauth2/clients
# On my private install...
# export ADMIN_ID=my:adminclient/42
# export ADMIN_SECRET="baby shark do do do-do do"

sed -e "s|CLIENT_ID|$CLIENT_ID|" -e "s|CLIENT_SECRET|$CLIENT_SECRET|" -e "s|ADMIN_ID|$ADMIN_ID|" -e "s|ADMIN_SECRET|$ADMIN_SECRET|" $1 > input.json
curl -k -X POST -H "Content-Type: application/json; charset=UTF-8" --data @input.json $SERVER > output.json
cat output.json


