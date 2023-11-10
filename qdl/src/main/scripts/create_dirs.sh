

QDL_ROOT=$NCSA_DEV_INPUT/qdl
OA4MP_ROOT=$NCSA_DEV_INPUT/oa4mp
OA4MP_QDL_ROOT=$NCSA_DEV_INPUT/oa4mp/qdl
OA4MP_SERVER_DEPLOY=$NCSA_DEV_OUTPUT/server
OA4MP_QDL_DEPLOY=$NCSA_DEV_OUTPUT/oa4mp-qdl

# First off is to run the actual QDL buyild to get the directories created
# with the documentation, QDL native modules etc. These have to be part of a distro

cd $QDL_ROOT/language/src/main/scripts
./create_dirs.sh $QDL_ROOT $OA4MP_QDL_DEPLOY
# That creates the basic directory structure. Now add OA4MP specific items

cd $OA4MP_QDL_DEPLOY
cd docs
echo "converting docs..."
lowriter --headless --convert-to pdf $OA4MP_QDL_ROOT/src/main/docs/qdl_oa4mp_store_access.odt
lowriter --headless --convert-to pdf $OA4MP_QDL_ROOT/src/main/docs/creating_claim_sources2.odt
lowriter --headless --convert-to pdf $OA4MP_QDL_ROOT/src/main/docs/claim_source_examples.odt
lowriter --headless --convert-to pdf $OA4MP_QDL_ROOT/src/main/docs/token_handler_configuration.odt
echo "...done!"