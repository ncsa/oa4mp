DEFAULT_SERVER=https://locahost/oauth2/oidc-cm
SERVER=http://localhost:44444/oauth2/oidc-cm
# On my private install...
export ADMIN_ID=my:adminclient/42
export ADMIN_SECRET="baby shark do do do-do do"
# Encoded token is base 64 encoded ADMIN_ID:ADMIN_SECRET

sed -e "s|CLIENT_ID|$CLIENT_ID|" -e "s|CLIENT_SECRET|$CLIENT_SECRET|" -e "s|ADMIN_ID|$ADMIN_ID|" -e "s|ADMIN_SECRET|$ADMIN_SECRET|" $1 > input.json
curl -k -X POST -H "Authorization: Bearer $(echo -n $ADMIN_ID:$ADMIN_SECRET | base64)" -H "Content-Type: application/json; charset=UTF-8" --data @input.json $SERVER > output.json
cat output.json


