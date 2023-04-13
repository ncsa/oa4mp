# Main script to build OA4MP

# Next coupld of directories are to let this script update all my
# local installs of these tools, so I have the latest version after each build

QDL_LOCAL_INSTALL=/home/ncsa/apps/qdl
OA2_LOCAL_INSTALL=/home/ncsa/apps/oa2
OA2_LOCAL_INSTALL=/home/ncsa/apps/oa2

export JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64
DEPLOY_ROOT=/home/ncsa/dev/temp-deploy
SVN_ROOT=/home/ncsa/dev/ncsa-git




OA4MP_ROOT=$SVN_ROOT/oa4mp
OA4MP_CLIENT_DEPLOY=$DEPLOY_ROOT/client
OA4MP_SERVER_DEPLOY=$DEPLOY_ROOT/server
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

cp oa2-cli-jar-with-dependencies.jar $OA4MP_SERVER_DEPLOY/oa2-cli.jar
cp oa2-client-jar-with-dependencies.jar $OA4MP_SERVER_DEPLOY/oa2-client.jar
cp jwt-jar-with-dependencies.jar $OA4MP_SERVER_DEPLOY/jwt.jar

cd $OA2_TOOLS/src/main/resources
cp *.sql $OA4MP_SERVER_DEPLOY
cd $OA2_TOOLS/src/main/scripts
cp * $OA4MP_SERVER_DEPLOY


cd $OA4MP_ROOT/qdl
mvn -P qdl package
mv target/oa2-qdl-jar-with-dependencies.jar target/qdl.jar
#/home/ncsa/dev/ncsa-git/qdl/language/src/main/scripts/create_installer.sh /home/ncsa/dev/ncsa-git/oa4mp/oa4mp-qdl /home/ncsa/dev/temp-deploy/oa2-qdl oa2-qdl-installer.jar
/home/ncsa/dev/ncsa-git/qdl/language/src/main/scripts/create_installer.sh $OA4MP_ROOT/qdl $DEPLOY_ROOT/oa2-qdl oa2-qdl-installer.jar


# Update local QDL install with the latest and greatest
#

cp target/qdl.jar $QDL_LOCAL_INSTALL/lib
cp /home/ncsa/dev/temp-deploy/oa2-qdl/lib/build-info.txt $QDL_LOCAL_INSTALL/lib

cd $OA4MP_SERVER_DEPLOY

# OA2 client and cli deploy to local system
cp oa2-cli.jar $OA2_LOCAL_INSTALL/lib
cp oa2-client.jar $OA2_LOCAL_INSTALL/lib

# Set up local install of cli and client.

cp $OA4MP_SERVER_DEPLOY/oa2-cli.jar $OA2_LOCAL_INSTALL/lib
cp $OA4MP_SERVER_DEPLOY/oa2-client.jar $OA2_LOCAL_INSTALL/lib