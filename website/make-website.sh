#
# Run this AFTER build.sh or it will fail.
#
OA4MP_ROOT=$NCSA_DEV_INPUT/oa4mp

GITHUB_ROOT=$OA4MP_ROOT/docs
$OA4MP_ROOT/website/convert-docs.sh $OA4MP_ROOT $GITHUB_ROOT/pdf


cd $OA4MP_ROOT || exit
# Fix https://github.com/ncsa/oa4mp/issues/262 Do ONE clean and do it here.
mvn clean
mvn javadoc:javadoc -Dmaven.javadoc.skip=false
mvn javadoc:aggregate
cd $OA4MP_ROOT/website || exit
mvn site
# Note the source directory in the next command has no apidocs subdirectory, so this overlays
# without overwriting.
cp -r $OA4MP_ROOT/target/site/* $GITHUB_ROOT
cp -r $OA4MP_ROOT/website/target/site/* $GITHUB_ROOT
