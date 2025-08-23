#!/bin/bash

######################################################################
# OAuth 2.0 Device Authorization Grant flow, a.k.a., Device Flow     #
# (RFC 8628 - https://datatracker.ietf.org/doc/html/rfc8628)         #
#                                                                    #
# Device flow decouples user-agent-based authorization (i.e., user   #
# login) from fetching tokens and user attributes. This script       #
# emulates a non-brower-based device. It contacts the device         #
# authorization endpoint to fetch a user code to be displayed to     #
# the user. The user then enters this user code in a web browser,    #
# confirms the user code and the scopes that were requested by the   #
# device, and logs in with a selected Identity Provider (IdP). The   #
# device polls the token endpoint for the user's authentication and  #
# then extracts user attributes from the returned id_token.          #
#                                                                    #
# There are several variables you must set below in the              #
# USER CONFIGURATION section, minimally CLIENT_ID and CLIENT_SECRET  #
# (if your client is a confidential client). Alternatively, you can  #
# comment out these values and set them in your shell's environment  #
# (e.g., export CLIENT_ID="cilogon:/client_id/abcdef1234567890").    #
#                                                                    #
# Note: This script can also be used to test Google's OAuth 2.0      #
# Device flow for TV and Limited-Input Device Applications. See      #
# https://developers.google.com/identity/protocols/oauth2/limited-input-device
# for details on obtaining credentials. Set CLIENT_ID and            #
# CLIENT_SECRET appropriately, and also set GOOGLE_CLIENT=1.         #
#                                                                    #
# Version: 1.1.0                                                     #
# Last Update: 2021-07-29                                            #
# Author: Terry Fleury <tfleury@cilogon.org>                         #
######################################################################


####################################
##### BEGIN USER CONFIGURATION #####
####################################
# CLIENT_ID is required for both confidential and public clients
CLIENT_ID="cilogon:/client_id/abcdef1234567890"
# For public clients, comment out CLIENT_SECRET
CLIENT_SECRET="my_client_secret"
# HOST is one of cilogon.org, test.cilogon.org, or dev.cilogon.org
HOST="cilogon.org"
# Comment out SCOPE to request the registered scopes for the CILogon client
SCOPE="openid email profile"
# Set GOOGLE_CLIENT=1 to test a Google "TV and Limited-Input Device" client
# using Google's device and token endpoints
GOOGLE_CLIENT=0
# DEBUG mode prints all curl calls and their raw output
DEBUG=0
##################################
##### END USER CONFIGURATION #####
##################################


# Do some basic checks
CHECKFAILED=0
if ! command -v curl &> /dev/null ; then
    echo "Please install the 'curl' program (https://curl.se/)."
    CHECKFAILED=1
fi
if ! command -v jq &> /dev/null ; then
    echo "Please install the 'jq' program v1.6 or higher (https://stedolan.github.io/jq/)."
    CHECKFAILED=1
else
    # jq version 1.6 is needed for 'base64d'
    JQVERSTR=`jq --version`
    [[ "${JQVERSTR}" =~ jq-([0-9])[.]([0-9]*) ]] && JQMAJ=${BASH_REMATCH[1]} && JQMIN=${BASH_REMATCH[2]}
    if [ "${#JQMAJ}" -eq "0" -o "${#JQMIN}" -eq "0" -o "${JQMAJ}" -lt "1" -o "${JQMIN}" -lt "6" ] ; then
        echo "Please install 'jq' version 1.6 or higher (https://stedolan.github.io/jq/)."
        CHECKFAILED=1
    fi
fi
if [ "${#CLIENT_ID}" -eq "0" ] ; then
    echo "Please set your CLIENT_ID at the top of the script."
    CHECKFAILED=1
fi
if [ "${#CLIENT_SECRET}" -eq "0" -a "${#SCOPE}" -gt "0" -a "${SCOPE}" != "openid" ] ; then
    echo "Public clients can request only the 'openid' scope."
    CHECKFAILED=1
fi
if [ "${#SCOPE}" -eq "0" -a "${GOOGLE_CLIENT}" -eq "1" ] ; then
    echo "Google requires at least one scope. Try SCOPE=\"openid email profile\"."
    CHECKFAILED=1
fi
if [ "${#HOST}" -eq "0" -a "${GOOGLE_CLIENT}" -ne "1" ] ; then
    echo "Please set the CILogon.org HOST at the top of the script."
    CHECKFAILED=1
fi
if [ "${CHECKFAILED}" -eq "1" ] ; then
    echo "Exiting."
    exit 1
fi

# A few declarations
if [ "${GOOGLE_CLIENT}" -eq "1" ] ; then
    DEVICE_ENDPOINT="https://oauth2.googleapis.com/device/code"
    TOKEN_ENDPOINT="https://oauth2.googleapis.com/token"
else
    DEVICE_ENDPOINT="https://${HOST}/oauth2/device_authorization"
    TOKEN_ENDPOINT="https://${HOST}/oauth2/token"
fi
function urldecode { : "${*//+/ }"; echo -e "${_//%/\\x}"; }
function jwtdecode { jq -R 'split(".") | .[1] | @base64d | fromjson' <<< "$1" ; }

# Contact the device_authorization endpoint to get a user_code
DATA=("client_id=${CLIENT_ID}")
if [ "${#CLIENT_SECRET}" -gt "0" ] ; then
    DATA+=("client_secret=${CLIENT_SECRET}")
fi
if [ "${#SCOPE}" -gt "0" ] ; then
    DATA+=("scope=${SCOPE}")
fi
CURL="curl -s"
for i in "${DATA[@]}" ; do
    CURL+=" --data-urlencode '$i'"
done
CURL+=" '${DEVICE_ENDPOINT}'"
if [ "${DEBUG}" -eq "1" ] ; then
    echo $CURL
fi
OUTPUT=`eval $CURL`
if [ "${DEBUG}" -eq "1" ] ; then
    echo $OUTPUT
fi

# Check if there was an error
ERROR=`echo "${OUTPUT}" | jq -r '.error'`
ERROR_DESCRIPTION=`echo "${OUTPUT}" | jq -r '.error_description'`
if [ "${ERROR}" != "null" ] ; then
    echo "ERROR: ${ERROR_DESCRIPTION}."
    exit 1
fi

# No error, so extract parameters from JSON
DEVICE_CODE=`echo "${OUTPUT}" | jq -r '.device_code'`
USER_CODE=`echo "${OUTPUT}" | jq -r '.user_code'`
EXPIRES_IN=`echo "${OUTPUT}" | jq -r '.expires_in'`
VERIFICATION_URI=`echo "${OUTPUT}" | jq -r '.verification_uri'`
VERIFICATION_URL=`echo "${OUTPUT}" | jq -r '.verification_url'`
VERIFICATION_URI_COMPLETE=`echo "${OUTPUT}" | jq -r '.verification_uri_complete'`
INTERVAL=`echo "${OUTPUT}" | jq -r '.interval'`
# If no interval returned, default to 5 seconds
if [ "${INTERVAL}" == "null" ] ; then
    INTERVAL=5
fi

# Ensure all required parameters were returned
CHECKFAILED=0
if [ "${DEVICE_CODE}" == "null" ] ; then
    echo "ERROR: No device_code found in the response."
    CHECKFAILED=1
fi
if [ "${USER_CODE}" == "null" ] ; then
    echo "ERROR: No user_code found in the response."
    CHECKFAILED=1
fi
if [ "${EXPIRES_IN}" == "null" ] ; then
    echo "ERROR: No expires_in found in the response."
    CHECKFAILED=1
fi
# Special check for Google which does not adhere to the spec
if [ "${VERIFICATION_URI}" == "null" -a "${VERIFICATION_URL}" != "null" ] ; then
    VERIFICATION_URI=${VERIFICATION_URL}
fi
if [ "${VERIFICATION_URI}" == "null" ] ; then
    echo "ERROR: No verification_uri found in the response."
    CHECKFAILED=1
fi
if [ "${CHECKFAILED}" -eq "1" ] ; then
    echo "Exiting."
    exit 1
fi

# Display relevant info to user
if [ "${DEBUG}" -eq "1" ] ; then
    echo "Device code is '${DEVICE_CODE}'."
    echo "Expires in '${EXPIRES_IN}' seconds."
    echo "Retry interval is '${INTERVAL}' seconds."
    echo "Verification URL is '${VERIFICATION_URI}'."
fi
echo "Your user code is '${USER_CODE}'."
echo "Open a web browser and navigate to:"
if [ "${VERIFICATION_URI_COMPLETE}" != "null" ] ; then
    echo "${VERIFICATION_URI_COMPLETE}"
    if ! command -v qrencode &> /dev/null ; then
        echo "Install the 'qrencode' program for QR code output."
    else
        qrencode -m 2 -t ansiutf8 <<< "${VERIFICATION_URI_COMPLETE}"
    fi
else
    echo "${VERIFICATION_URI}"
fi
echo

# Contact the token endpoint, wait until user enters user_code and logs on
DATA=("client_id=${CLIENT_ID}")
if [ "${#CLIENT_SECRET}" -gt "0" ] ; then
    DATA+=("client_secret=${CLIENT_SECRET}")
fi
DATA+=("grant_type=urn:ietf:params:oauth:grant-type:device_code")
DATA+=("device_code=${DEVICE_CODE}")
CURL="curl -s"
for i in "${DATA[@]}" ; do
    CURL+=" --data-urlencode '$i'"
done
CURL+=" '${TOKEN_ENDPOINT}'"
if [ "${DEBUG}" -eq "1" ] ; then
    echo $CURL
fi

TIME=`date +%s`
TIMELEFT=${EXPIRES_IN}
SUCCESS=0

echo "Waiting for user authentication."
while [ "${TIMELEFT}" -gt "0" -a "${SUCCESS}" -eq "0" ] ; do
    printf "\033[K${TIMELEFT} seconds remaining, sleeping ${INTERVAL}..."

    OUTPUT=`eval $CURL`
    if [ "${DEBUG}" -eq "1" ] ; then
        echo $OUTPUT
    fi

    # Check for error responses; includes "authorization_pending"
    ERROR=`echo "${OUTPUT}" | jq -r '.error'`
    ERROR_DESCRIPTION=`echo "${OUTPUT}" | jq -r '.error_description'`

    if [ "${ERROR}" != "null" ] ; then
        printf " ${ERROR_DESCRIPTION}\033[65D"
        if [ "${ERROR}" == "authorization_pending" -o "${ERROR}" == "slow_down" ] ; then
            # For "slow_down", spec requires increasing interval by 5
            if [ "${ERROR}" == "slow_down" ] ; then
                INTERVAL=`expr $INTERVAL + 5`
            fi
            sleep "${INTERVAL}"
            NOW=`date +%s`
            TIMELEFT=`expr $EXPIRES_IN - $NOW + $TIME`
        else
            if [ "${ERROR_DESCRIPTION}" == "no pending request" ] ; then
                printf "\nERROR: User denied the user_code.\n"
                printf "Please begin a new device code request.\n"
            else
                printf "\nERROR: ${ERROR_DESCRIPTION}.\n"
                if [ "${ERROR_DESCRIPTION}" == "device_code expired" ] ; then
                    printf "Please begin a new device code request.\n"
                fi
            fi
            exit 1
        fi
    else
        printf " Done!\n"
        SUCCESS=1
    fi
done

if [ "${SUCCESS}" -eq "0" ] ; then
    echo "ERROR: Timed out. The user_code has expired."
    echo "Please begin a new device code request."
    exit 1
fi

# Find and decode the id_token in the response from the token endpoint
ID_TOKEN=`echo "${OUTPUT}" | jq -r '.id_token'`
if [ "${ID_TOKEN}" == "null" ] ; then
    echo "ERROR: No id_token found in response."
    exit 1
fi

# Finally, pretty print the user attributes
JWT=$(jwtdecode "${ID_TOKEN}")
echo "${JWT}" | jq '.'

