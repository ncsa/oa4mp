#
# Run this AFTER build.sh or it will fail.
#
OA4MP_ROOT=$NCSA_DEV_INPUT/oa4mp

GITHUB_ROOT=$OA4MP_ROOT/docs
cd $GITHUB_ROOT/pdf

echo "converting docs to PDF"

lowriter --headless --convert-to pdf ~/dev/ncsa-git/oa4mp/qdl/src/main/docs/qdl_oa4mp_store_access.odt
lowriter --headless --convert-to pdf ~/dev/ncsa-git/oa4mp/qdl/src/main/docs/creating_claim_sources2.odt
lowriter --headless --convert-to pdf ~/dev/ncsa-git/oa4mp/qdl/src/main/docs/claim_source_examples.odt
lowriter --headless --convert-to pdf ~/dev/ncsa-git/oa4mp/qdl/src/main/docs/token_handler_configuration.odt
echo "done converting PDFs"

# ===============
cd $OA4MP_ROOT
mvn javadoc:javadoc -Dmaven.javadoc.skip=false
mvn clean javadoc:aggregate
cd $OA4MP_ROOT/website
mvn clean site
# Note the source directory in the next command has no apidocs subdirectory, so this overlays
# without overwriting.
cp -r $OA4MP_ROOT/target/site/* $GITHUB_ROOT
cp -r $OA4MP_ROOT/website/target/site/* $GITHUB_ROOT
