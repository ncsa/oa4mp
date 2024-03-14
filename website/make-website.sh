#
# Run this AFTER build.sh or it will fail.
#
OA4MP_ROOT=$NCSA_DEV_INPUT/oa4mp

GITHUB_ROOT=$OA4MP_ROOT/docs
./convert-docs.sh $OA4MP_ROOT $GITHUB_ROOT/pdf


cd $OA4MP_ROOT || exit
mvn javadoc:javadoc -Dmaven.javadoc.skip=false
mvn clean javadoc:aggregate
cd $OA4MP_ROOT/website || exit
mvn clean site
# Note the source directory in the next command has no apidocs subdirectory, so this overlays
# without overwriting.
cp -r $OA4MP_ROOT/target/site/* $GITHUB_ROOT
cp -r $OA4MP_ROOT/website/target/site/* $GITHUB_ROOT
