# This will create the server installer for OA4MP. It includes the basic files
# for an installation, including the cli, a basic configuration file,
# qdl scripts for databases etc.
#
# This is a work in progress and not ready at all for use yet.
#

DEFAULT_OA4MP_ROOT=$NCSA_DEV_INPUT/oa4mp
DEFAULT_TARGET_ROOT="/home/ncsa/dev/temp-deploy/server/install"
DEFAULT_JAR_NAME="oa4mp-installer.jar"

if [[  "$1" = "--help" ]];then
  echo "create_installer.sh [root target jar_name]"
  echo "create the installable jar for OA4MP."
  echo "No arguments means to use the OA4MP root (assumes there are already files there) named '$DEFAULT_OA4MP_ROOT'"
   echo "and create the directories in   '$DEFAULT_TARGET_ROOT'"
   echo "The result will be a jar named '$DEFAULT_JAR_NAME"
  exit 1
fi


# **IF** there are arguments for the target of this, use them. Otherwise use the default
OA4MP_ROOT=${1:-$DEFAULT_OA4MP_ROOT}
ADMIN_ROOT=$OA4MP_ROOT/server-admin/src/main
TARGET_ROOT=${2:-$DEFAULT_TARGET_ROOT}
JAR_NAME=${3:-$DEFAULT_JAR_NAME}

echo "cleaning out old deploy in " $DEPLOY_ROOT
if [ ! -d "$TARGET_ROOT" ]; then
    mkdir "$TARGET_ROOT"
fi
cd $TARGET_ROOT
rm -Rf *

mkdir edu
mkdir edu/uiuc
mkdir edu/uiuc/ncsa
mkdir edu/uiuc/ncsa/qdl
mkdir edu/uiuc/ncsa/qdl/install


cd $TARGET_ROOT
cp $NCSA_DEV_INPUT/qdl/language/src/main/scripts/installer.mf .
cp $NCSA_DEV_INPUT/qdl/language/src/main/scripts/version.txt .
cp $NCSA_DEV_INPUT/qdl/language/target/classes/edu/uiuc/ncsa/qdl/install/Installer.class edu/uiuc/ncsa/qdl/install

# Now make the directories
mkdir "bin"
cp $ADMIN_ROOT/scripts/cli .
cp $ADMIN_ROOT/scripts/clc .

mkdir "etc"
cp $ADMIN_ROOT/resources/oa4mp-*.* .
mkdir "lib"
cp "$OA4MP_ROOT/target/qdl.jar" lib
cd lib
# Get the actual manifest so that build info is available.
unzip qdl.jar "*.MF"
# Puts it in the main qdl directory. Should be exactly one file in it.
mv META-INF/MANIFEST.MF build-info.txt
rmdir META-INF/

cd ..
mkdir "log"
mkdir "var"
# jar cmf manifest-file jar-file input-files
#jar cmf installer.mf $JAR_NAME edu/uiuc/ncsa/qdl/install/Installer.class version.txt  build-info.txt bin docs etc lib log var examples
jar cmf installer.mf $JAR_NAME edu/uiuc/ncsa/qdl/install/Installer.class version.txt  bin docs etc lib log var examples
