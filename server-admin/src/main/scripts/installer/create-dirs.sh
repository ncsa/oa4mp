# This creates the directory structure for creating OA4MP from the sources.
#
#
DEFAULT_OA4MP_ROOT=$NCSA_DEV_INPUT/oa4mp
DEFAULT_OA4MP_ROOT_SOURCES=$NCSA_DEV_INPUT/oa4mp/server-admin
DEFAULT_TARGET_ROOT=$NCSA_DEV_OUTPUT/oa4mp-install
DEFAULT_JAR_NAME="oa4mp-installer.jar"
# The next is where the full build places the constructed wars and jars.
OA4MP_SERVER_DEPLOY=$NCSA_DEV_OUTPUT/oa4mp

if [[  "$1" = "--help" ]];then
  echo "create_dirs.sh [oa4mp_root target_dir]"
  echo "create the diectory structure and populate it for OA4MP. You may then run the"
  echo "create_installer.sh to create the actual jar."
  echo "No arguments means to use the root (assumes there are already files there) named '$DEFAULT_OA4MP_ROOT'"
   echo "and create the directories in   '$DEFAULT_TARGET_ROOT'"
   echo "The result will be a jar named '$DEFAULT_JAR_NAME"
  exit 1
fi

echo "  creating targer dirs for installer"
# **IF** there are arguments for the target of this, use them. Otherwise use the default
OA4MP_ROOT=${1:-$DEFAULT_OA4MP_ROOT}
TARGET_ROOT=${2:-$DEFAULT_TARGET_ROOT}

if [ ! -d "$TARGET_ROOT" ]
  then
    mkdir "$TARGET_ROOT"
    if [ $? -eq 0 ]; then
        echo $TARGET_ROOT created
    else
        echo $TARGET_ROOT could not be created, exiting...
        exit 1
    fi
   else
    echo "  deploy target directory exists, cleaning..."
    cd $TARGET_ROOT
    rm -Rf *
fi

cd $TARGET_ROOT || exit
#rm -Rf *

mkdir org
mkdir org/oa4mp
mkdir org/oa4mp/server
mkdir org/oa4mp/server/admin
mkdir org/oa4mp/server/admin/install

cd $TARGET_ROOT || exit
cp $DEFAULT_OA4MP_ROOT_SOURCES/src/main/scripts/installer/installer.mf .
cp $DEFAULT_OA4MP_ROOT_SOURCES/src/main/scripts/installer/version.txt .
# following class has to be installed here so it executes later.
cp "$DEFAULT_OA4MP_ROOT_SOURCES"/target/classes/org/oa4mp/server/admin/install/*.class org/oa4mp/server/admin/install
# cp "$QDL_SOURCES"/target/classes/org/qdl_lang/install/*.class org/qdl_lang/install


# Now make the directories
mkdir "bin"
cd "bin" || exit
cp $DEFAULT_OA4MP_ROOT_SOURCES/src/main/scripts/installer/clc .
cp $DEFAULT_OA4MP_ROOT_SOURCES/src/main/scripts/installer/cli .
cp $DEFAULT_OA4MP_ROOT_SOURCES/src/main/scripts/installer/jwt .
cp $DEFAULT_OA4MP_ROOT_SOURCES/src/main/scripts/installer/migrate .
cd ..
mkdir "docs"
cd "docs" || exit
# assumes the website was created
cp $OA4MP_ROOT/docs/pdf/*.pdf .
cd ..
mkdir "etc"
cd "etc"
cp $DEFAULT_OA4MP_ROOT_SOURCES/src/main/scripts/installer/cfg.xml .
cp $DEFAULT_OA4MP_ROOT_SOURCES/src/main/scripts/installer/client-cfg.xml .
cp $DEFAULT_OA4MP_ROOT_SOURCES/src/main/scripts/installer/create_keys.cmd .
cp $OA4MP_SERVER_DEPLOY/*.sql .
cp $OA4MP_SERVER_DEPLOY/oa4mp-subject.template .
cp $OA4MP_SERVER_DEPLOY/oa4mp-message.template .
cd  ..

mkdir "lib"
cd lib || exit
cp $OA4MP_SERVER_DEPLOY/*.jar .
cd ..
mkdir examples
cd examples || exit
cp $OA4MP_SERVER_DEPLOY/*.tar .
cd ..
mkdir "log"
mkdir "lib/cp"
mkdir "var"
mkdir "var/storage"
mkdir "var/storage/client"
mkdir "var/storage/server"
mkdir qdl
mkdir qdl/scripts

mkdir "wars"
cd wars || exit
cp $OA4MP_SERVER_DEPLOY/*.war .

echo "   ...done!"

