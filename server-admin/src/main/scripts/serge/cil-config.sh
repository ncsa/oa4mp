# After the update to the new wars has been made,
# wait a minute for Tomcat to detect the changes

export SOURCE_DIR=/home/jgaynor/downloads
export TARGET_DIR=/var/lib/tomcat9/webapps
export BASE_WAR=$SOURCE_DIR/cilogon-oa2-client.war

targets=("cilogon-oa2-polo1" "cilogon-oa2-polo2" "cilogon-oa2-polo3" "cilogon-oa2-test" "cilogon-oa2-dev" "lsst-client"
"lsst-test-linking" "lsst-test-onboarding" "lsst-prod-linking" "lsst-prod-onboarding")

for i in "${!targets[@]}"; do

  cd $TARGET_DIR/${targets[$i]}/WEB-INF
  sed -i "s/cilogon-oa2/${targets[$i]}/g" web.xml
done

service tomcat9 restart
