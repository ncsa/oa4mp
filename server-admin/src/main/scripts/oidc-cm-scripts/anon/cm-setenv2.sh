#!/bin/bash
# This file contains the environment variables for the service. Set them here and they should
# get picked up by each script as needed (this assumes everything is being run from the current
# directory).

# Tip: If you are working with several different clients, you may want to comment out the
# setting REGISTRATION_URI so it does not get set to what is here.

# export SERVER=https://cilogon.org/oauth2/oidc-cm
# export CLIENT_ID=put-your-id-here
# export CLIENT_SECRET=put-your-secret-here
# export REGISTRATION_URI="https://cilogon.org/oauth2/oidc-cm?client_id=put-client-id-here"

# We set the bearer token here so it is available subsequently. This is the least problematic way to
# do this since it is easy to get the escaping wrong.

# Next line is for debugging. Just remove it if it is here and set your own values above.
source /home/ncsa/dev/csd/config/oidc-cm-setenv2.sh

# Slightly kludgy: There is NO bash way to URL encode/decode at the command line.
# At least without a substantial detour to something like sed
# and a very messy (as in fragile) reg ex.
# The spec says the bearer token is
# base64_encode(url_encode(CLIENT_ID):url_encode(CLIENT_SECRET))
# In point of fact, OA4MP ids and tokens are invariant under url decode:
# CLIENT_ID == url_decode(CLIENT_ID), CLIENT_SECRET == url_decode(CLIENT_SECRET)
# which we use here.
# So if this ever breaks because the ids or secrets change, this is why.

export BEARER_TOKEN=$(echo -n $CLIENT_ID:$CLIENT_SECRET | base64 -w 0)
