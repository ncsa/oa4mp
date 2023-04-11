# shell script to hammer the server with hundreds of requests. This is to test database connection pooling.

URL="https://localhost:9443/oauth2/authorize?scope=org.cilogon.userinfo+openid+profile+email&response_type=code&redirect_uri=https%3A%2F%2Flocalhost%3A9443%2Fclient42%2Fready&state=DGYQsBDx9zrojd4-I1DsiuBR0HcpKO6G_9dPzLcbVxc&nonce=pP9hGXE0qIg5UddJCazQpN1dOPJZ1_tsUn4dVTtl-3A&prompt=login&client_id=localhost%3Acommand.line"
for i in $(seq 1 300); do \
    echo $i && curl --no-sessionid -s ${URL} -o /tmp/$i.html &
    
    
