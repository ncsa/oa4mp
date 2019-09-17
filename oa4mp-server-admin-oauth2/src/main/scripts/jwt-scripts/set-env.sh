#!/bin/bash
# This file contains the environment variables for the service. Set them here and they should
# get picked up by each script as needed (this assumes everything is being run from the current
# directory).

export JWT_JAR=/home/ncsa/dev/ncsa-git/oa4mp/oa4mp-server-admin-oauth2/target/jwt-jar-with-dependencies.jar

# Next line is for debugging -- it pulls in custom stuff that should not end up ina VCS.
# Just remove it if it is here and set your own values above.
source /home/ncsa//dev/rokwire/auth/my-env.sh
