# DEFAULT_SERVER=https://locahost/oauth2/clients
# SERVER=http://localhost:44444/oauth2/clients
sed -e "s|CLIENT_ID|$CLIENT_ID|" -e "s|CLIENT_SECRET|$CLIENT_SECRET|" -e "s|ADMIN_ID|$ADMIN_ID|" -e "s|ADMIN_SECRET|$ADMIN_SECRET|" $1 > input.json
curl -X POST -H "Content-Type: application/json; charset=UTF-8" --data @input.json $SERVER > output.json
cat output.json


