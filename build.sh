# Main script to build OA4MP

# Next couple of directories are to let this script update all my
# local installs of these tools, so I have the latest version after each build

OA4MP_ROOT=$NCSA_DEV_INPUT/oa4mp
OA4MP_CLIENT_DEPLOY=$NCSA_DEV_OUTPUT/client
OA4MP_SERVER_DEPLOY=$NCSA_DEV_OUTPUT/server
OA2_TOOLS=$OA4MP_ROOT/server-admin

cd $OA4MP_ROOT
mvn clean install

if [[ $? -ne 0 ]] ; then
    echo "OA4MP maven build failed, exiting..."
    exit 1
fi

cp $OA4MP_ROOT/client-oauth2/target/client2.war $OA4MP_CLIENT_DEPLOY
cp $OA4MP_ROOT/client-oauth2/src/main/resources/*.sql $OA4MP_CLIENT_DEPLOY
cp $OA4MP_ROOT/oa4mp-server-oauth2/target/oauth2.war  $OA4MP_SERVER_DEPLOY

cd $OA2_TOOLS
mvn -P cli package
mvn -P client package
mvn -P jwt package
cd $OA2_TOOLS/target

cp cli-jar-with-dependencies.jar $OA4MP_SERVER_DEPLOY/cli.jar
cp clc-jar-with-dependencies.jar $OA4MP_SERVER_DEPLOY/clc.jar
cp jwt-jar-with-dependencies.jar $OA4MP_SERVER_DEPLOY/jwt.jar

cd $OA2_TOOLS/src/main/resources
cp *.sql $OA4MP_SERVER_DEPLOY
cd $OA2_TOOLS/src/main/scripts
cp * $OA4MP_SERVER_DEPLOY


cd $OA4MP_ROOT/qdl
mvn -P qdl package
mv target/oa2-qdl-jar-with-dependencies.jar target/qdl.jar
$NCSA_DEV_INPUT/qdl/language/src/main/scripts/create_installer.sh $OA4MP_ROOT/qdl $NCSA_DEV_OUTPUT/oa2-qdl oa2-qdl-installer.jar


# Update local QDL install with the latest and greatest
#

cp target/qdl.jar $QDL_HOME/lib
cp /home/ncsa/dev/temp-deploy/oa2-qdl/lib/build-info.txt $QDL_HOME/lib

cd $OA4MP_SERVER_DEPLOY

# OA2 client and cli deploy to local system
cp cli.jar $OA2_LOCAL_INSTALL/lib
cp clc.jar $OA2_LOCAL_INSTALL/lib

# Set up local install of cli and client.

cp $OA4MP_SERVER_DEPLOY/cli.jar $OA2_LOCAL_INSTALL/lib
cp $OA4MP_SERVER_DEPLOY/clc.jar $OA2_LOCAL_INSTALL/lib