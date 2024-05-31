# Script to update the clients on serge. See the cil-readme.txt file
# in this directory.
export SOURCE_DIR=/home/jgaynor/downloads
export TARGET_DIR=/var/lib/tomcat9/webapps
export BASE_WAR=$SOURCE_DIR/cilogon-oa2-client.war

targets=("cilogon-oa2" "cilogon-oa2-polo1" "cilogon-oa2-polo2" "cilogon-oa2-polo3" "cilogon-oa2-test" "cilogon-oa2-dev" "lsst-client"
"lsst-test-linking" "lsst-test-onboarding" "lsst-prod-linking" "lsst-prod-onboarding")

for i in "${!targets[@]}"; do
  cp $BASE_WAR $TARGET_DIR/${targets[$i]}.war
done

cp $SOURCE_DIR/oauth2.war $TARGET_DIR