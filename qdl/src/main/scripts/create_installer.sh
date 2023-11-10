# NOTE this pre-supposes that you have done a full build of QDL and are making the full
# distro for OA4MP's version of QDL.  If you just need to runnable jar, that is created
# using the qdl profile and
# and resides in oa4mp/qdl/target
OA4MP_QDL_ROOT=$NCSA_DEV_INPUT/oa4mp/qdl
OA4MP_QDL_DEPLOY=$NCSA_DEV_OUTPUT/oa4mp-qdl
DEFAULT_JAR_NAME="qdl-installer.jar"

JAR_NAME=${1:-$DEFAULT_JAR_NAME}

./create_dirs.sh

cd $OA4MP_QDL_ROOT
mvn -P qdl package > mvn.log
cp "$OA4MP_QDL_ROOT/target/oa4mp-qdl-jar-with-dependencies.jar" $OA4MP_QDL_DEPLOY/lib/qdl.jar
unzip -p "$OA4MP_QDL_ROOT/target/oa4mp-qdl-jar-with-dependencies.jar" META-INF/MANIFEST.MF > $OA4MP_QDL_DEPLOY/lib/build-info.txt

cd $OA4MP_QDL_DEPLOY
# Get the actual manifest so that build info is available.
jar cmf installer.mf "$JAR_NAME" edu/uiuc/ncsa/qdl/install/Installer.class version.txt  bin docs etc lib log var examples

