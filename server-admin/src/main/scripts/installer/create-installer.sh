# This will create the massive installer for OA4MP.
# All the files (including wars and jars) are here.
# The net result is a jar of over 200 Mb.
# The QDL distro installer is in qdl/src/main/scripts.
# This includes the basic files
# for an installation, including qdl, qdl-run, a basic configuration file,
#
#
OA4MP_SOURCES=$NCSA_DEV_INPUT/oa4mp
OA4MP_ROOT=$NCSA_DEV_INPUT/oa4mp
TARGET_ROOT=$NCSA_DEV_OUTPUT/oa4mp-install
JAR_NAME="oa4mp-installer.jar"

echo 'creating OA4MP installer'
cd $OA4MP_SOURCES/server-admin/src/main/scripts/installer || exit
./create-dirs.sh > installer.log
if [ $? -ne 0 ]
then
  echo "error running create dirs, see $OA4MP_SOURCES/server-admin/src/main/scripts/installer/installer.log " >&2
  exit 1;
fi


# Get the actual manifest so that build info is available.
cd $TARGET_ROOT || exit
java  edu.uiuc.ncsa.install.ListDistroFiles $TARGET_ROOT
jar cmf installer.mf "$JAR_NAME" edu/uiuc/ncsa/install/Installer.class dir_list.txt file_list.txt bin docs etc examples installer.mf lib log var version.txt wars

echo '     ... done!'
