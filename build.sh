# Main script to build OA4MP

# Next couple of directories are to let this script update all my
# local installs of these tools, so I have the latest version after each build
#
#  OA4MP_ROOT = root of sources
#  OA4MP_CLIENT_DEPLOY = where client artifacts are put
#  OA4MP_SERVER_DEPLOY = where server artifacts are put
#  OA4MP_QDL_ROOT = where QDL artifacts are put
#
if [ -z ${NCSA_DEV_INPUT+x} ]
  then
    echo "no sources, skipping..."
    exit 1
fi

if [ -z ${NCSA_DEV_OUTPUT+x} ]
  then
    echo "no output directory, skipping..."
    exit 1
fi


OA4MP_ROOT=$NCSA_DEV_INPUT/oa4mp
OA4MP_CLIENT_DEPLOY=$NCSA_DEV_OUTPUT/client
OA4MP_SERVER_DEPLOY=$NCSA_DEV_OUTPUT/server

if [ ! -d "$OA4MP_ROOT" ]
  then
    echo "$OA4MP_ROOT does not exist. No sources,  exiting.."
    exit 1
   else
     echo "$OA4MP_ROOT" exists
fi

if [ ! -d "$OA4MP_CLIENT_DEPLOY" ]
  then
    mkdir "$OA4MP_CLIENT_DEPLOY"
   else
    echo "$OA4MP_CLIENT_DEPLOY" exists
fi


if [ ! -d "$OA4MP_SERVER_DEPLOY" ]; then
   mkdir "$OA4MP_SERVER_DEPLOY"
   else
     echo "$OA4MP_SERVER_DEPLOY" exists
fi




# next line is so the profiles for the tools can be found in the source and built.
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

