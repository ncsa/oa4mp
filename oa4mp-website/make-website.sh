#
# Run this AFTER build.sh or it will fail.
#
export JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64
OA4MP_ROOT=/home/ncsa/dev/ncsa-git/oa4mp

WEBSITE_ROOT=$OA4MP_ROOT/docs
cd $WEBSITE_ROOT/pdf

echo "converting docs to PDF"

lowriter --headless --convert-to pdf ~/dev/ncsa-git/oa4mp/oa4mp-qdl/src/main/docs/qdl_oa4mp_store_access.odt
lowriter --headless --convert-to pdf ~/dev/ncsa-git/oa4mp/oa4mp-qdl/src/main/docs/creating_claim_sources2.odt
lowriter --headless --convert-to pdf ~/dev/ncsa-git/oa4mp/oa4mp-qdl/src/main/docs/claim_source_examples.odt
lowriter --headless --convert-to pdf ~/dev/ncsa-git/oa4mp/oa4mp-qdl/src/main/docs/token_handler_configuration.odt
echo "done converting PDFs"

# ===============
cd $OA4MP_ROOT
mvn javadoc:javadoc
cp -r $OA4MP_ROOT/language/target/site/apidocs/* $WEBSITE_ROOT/apidocs
cd $OA4MP_ROOT/website
mvn clean site
# Note the source directory in the next command has no apidocs subdirectory, so this overlays
# without overwriting.
cp -r $OA4MP_ROOT/website/target/site/* $WEBSITE_ROOT
