# Main script to build OA4MP

# Next couple of directories are to let this script update all my
# local installs of these tools, so I have the latest version after each build
#
#  OA4MP_ROOT = root of sources
#  OA4MP_CLIENT_DEPLOY = where client artifacts are put
#  OA4MP_SERVER_DEPLOY = where server artifacts are put
#
#  N.B. QDL is built and deployed in the build-tools script
echo "building OA4MP from sources ..."
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
OA4MP_CLIENT_DEPLOY=$NCSA_DEV_OUTPUT/oa4mp
OA4MP_SERVER_DEPLOY=$NCSA_DEV_OUTPUT/oa4mp


if [ ! -d "$OA4MP_ROOT" ]
  then
     echo "$OA4MP_ROOT does not exist. No sources,  exiting.."
     exit 1
fi


if [ ! -d "$OA4MP_SERVER_DEPLOY" ]
  then
    mkdir "$OA4MP_SERVER_DEPLOY"
   else
    echo "   deploy directory exists, cleaning..."
    cd $OA4MP_SERVER_DEPLOY || exit
    rm -Rf *
fi
if [[ $? -ne 0 ]] ; then
    echo "could not create clean directories in $OA4MP_SERVER_DEPLOY"
    exit 1
fi



# next line is so the profiles for the tools can be found in the source and built.
OA2_TOOLS=$OA4MP_ROOT/server-admin

cd $OA4MP_ROOT || exit
# echo  "╔══════════════╗"
# echo  "║Skipping tests║"
# echo  "╚══════════════╝"
# mvn clean install -DskipTests > maven.log

mvn clean install  > maven.log

if [[ $? -ne 0 ]] ; then
    echo "OA4MP build failed, see $OA4MP_ROOT/maven.log"
    exit 1
fi
echo "      ... done!"

cp $OA4MP_ROOT/client-oauth2/target/client2.war $OA4MP_CLIENT_DEPLOY
cp $OA4MP_ROOT/oa4mp-server-oauth2/target/oauth2.war  $OA4MP_SERVER_DEPLOY

QDL_OA2_TOOLS=$OA4MP_ROOT/qdl


echo "building OA4MP tools..."
cd $OA2_TOOLS || exit
mvn -P cli package > cli.log
if [[ $? -ne 0 ]] ; then
    echo "could not build cli, see $OA2_TOOLS/cli.log"
    exit 1
fi

mvn -P jwt package > jwt.log
if [[ $? -ne 0 ]] ; then
    echo "could not build jwt, see $OA2_TOOLS/jwt.log"
    exit 1
fi

mvn -P migrate package > migrate.log
if [[ $? -ne 0 ]] ; then
    echo "could not build migrate, see $OA2_TOOLS/migrate.log"
    exit 1
fi


cd $OA2_TOOLS/target || exit
echo "   deploying OA4MP tools..."

cp cli-jar-with-dependencies.jar $OA4MP_SERVER_DEPLOY/cli.jar
cp jwt-jar-with-dependencies.jar $OA4MP_SERVER_DEPLOY/jwt.jar
cp migrate-jar-with-dependencies.jar $OA4MP_SERVER_DEPLOY/fs-migrate.jar

echo "building OA4MP server installer..."

cd $OA4MP_ROOT/server-installer || exit
mvn -P installer package > server-installer.log
if [[ $? -ne 0 ]] ; then
    echo "could not build server-installer. See $OA4MP_ROOT/server-installer/server-installer.log"
    exit 1
fi
cp target/server-installer-jar-with-dependencies.jar $OA4MP_SERVER_DEPLOY/server-installer.jar

echo "building OA4MP client installer..."

cd $OA4MP_ROOT/client-installer || exit
mvn -P installer package > client-installer.log
if [[ $? -ne 0 ]] ; then
    echo "could not build client-installer. See $OA4MP_ROOT/client-installer/client-installer.log"
    exit 1
fi
cp target/client-installer-jar-with-dependencies.jar $OA4MP_SERVER_DEPLOY/client-installer.jar

echo "building RFC 8414 (well-known) support ..."
cd $OA4MP_ROOT/rfc8414 || exit
mvn -P installer package > rfc8414.log
if [[ $? -ne 0 ]] ; then
    echo "could not build RFC 8414 war. See $OA4MP_ROOT/rfc8414/rfc8414.log"
    exit 1
fi
cp target/well-known.war $OA4MP_SERVER_DEPLOY/well-known.war


echo "building QDL OA4MP tools..."
cd $QDL_OA2_TOOLS || exit
mvn -P client package > tools.log
if [[ $? -ne 0 ]] ; then
    echo "could not build QDL tools, see $QDL_OA2_TOOLS/tools.log"
    exit 1
fi
cd target
cp clc-jar-with-dependencies.jar $OA4MP_SERVER_DEPLOY/clc.jar


cd $OA2_TOOLS/src/main/resources
cp *.sql $OA4MP_SERVER_DEPLOY
cp oa4mp-message.template $OA4MP_SERVER_DEPLOY
cp oa4mp-subject.template $OA4MP_SERVER_DEPLOY
cd $OA2_TOOLS/src/main/scripts
if [ -f oidc-cm-scripts.tar ]
then
  rm oidc-cm-scripts.tar
fi
tar cf oidc-cm-scripts.tar oidc-cm-scripts/
if [ -f jwt-scripts.tar ]

then
  rm jwt-scripts.tar
fi
tar cf jwt-scripts.tar jwt-scripts/

cp cli $OA4MP_SERVER_DEPLOY
cp clc $OA4MP_SERVER_DEPLOY
cp oidc-cm-scripts.tar $OA4MP_SERVER_DEPLOY
cp jwt-scripts.tar $OA4MP_SERVER_DEPLOY
echo "     ... done!"

