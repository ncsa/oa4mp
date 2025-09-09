# This creates the distribution jar archive for OA4MP server.
# it contains all of the files in the current distribution
# in the correct directories and is designed to be referenced
# by the web installer.
# It does not contain the other jars or wars.
# It creates a temporary directory, writes everything to try,
# then jars that up and puts it in the server deploy directory

# OA4MP_ADMIN_SOURCES = the server-admin directory where the
#                       definitive versions of some thing live
# OA4MP_SERVER_SOURCES = the server installer directory

DEFAULT_OA4MP_ROOT=$NCSA_DEV_INPUT/oa4mp
OA4MP_ADMIN_SOURCES=$NCSA_DEV_INPUT/oa4mp/server-admin
OA4MP_SERVER_SOURCES=$NCSA_DEV_INPUT/oa4mp/server-installer/
JAR_NAME="server-archive.jar"
# The next is where the full build places the constructed wars and jars.
OA4MP_SERVER_DEPLOY=$NCSA_DEV_OUTPUT/oa4mp

if [[  "$1" = "--help" ]];then
  echo "create_distro.sh [oa4mp_root]"
  echo "create the directory structure and populate it for OA4MP. You may then run the"
  echo "create_installer.sh to create the actual jar."
  echo "No arguments means to use the root of the entire OA4MP source tree "
  echo "(assumes there are already files there) named '$DEFAULT_OA4MP_ROOT'"
  echo "The result will be a jar named '$JAR_NAME"
  exit 1
fi
cd "/tmp/"
cd $(mktemp -d) || exit
TEMP_DIR=$PWD
echo "  creating target dirs for installer in $PWD"
# **IF** there are arguments for the target of this, use them. Otherwise use the default
OA4MP_ROOT=${1:-$DEFAULT_OA4MP_ROOT}

echo "OA4MP Version: 6.2.1" > version.txt

# Now make the directories
mkdir "bin"
cd "bin" || exit
cp $OA4MP_ADMIN_SOURCES/src/main/scripts/installer/cli .
cp $OA4MP_ADMIN_SOURCES/src/main/scripts/installer/jwt .
cp $OA4MP_ADMIN_SOURCES/src/main/scripts/installer/migrate .
cd ..
mkdir "docs"
cd "docs" || exit
# assumes the website was created
cp $OA4MP_ROOT/docs/pdf/*.pdf .
cd ..
mkdir "etc"
cd "etc"
cp $OA4MP_SERVER_SOURCES/src/main/resources/installer/cfg.xml .
cp $OA4MP_SERVER_SOURCES/src/main/resources/installer/create_keys.cmd .
cp $OA4MP_ADMIN_SOURCES/src/main/resources/*.sql .
cp $OA4MP_ADMIN_SOURCES/src/main/resources/oa4mp-subject.template .
cp $OA4MP_ADMIN_SOURCES/src/main/resources/oa4mp-message.template .
cp $OA4MP_ADMIN_SOURCES/src/main/resources/derby-setup.txt .
cd $TEMP_DIR || exit
mkdir "lib"
mkdir "lib/cp"
mkdir "examples"
mkdir "log"
mkdir "var"
mkdir "var/storage"
mkdir "var/storage/file_store"
mkdir "var/storage/derby"
mkdir "qdl"
mkdir "qdl/scripts"

# Make the example tarballs
cd $OA4MP_ADMIN_SOURCES/src/main/scripts
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

mv jwt-scripts.tar  $TEMP_DIR/examples
mv oidc-cm-scripts.tar  $TEMP_DIR/examples

cd $TEMP_DIR

jar cf  "$JAR_NAME" bin docs etc examples qdl lib log var version.txt

mv $JAR_NAME $OA4MP_SERVER_DEPLOY
echo "   ...done!"

