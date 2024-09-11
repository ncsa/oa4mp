# This takes two arguments --
# 1 = the root docs directory of the install where the documents are found
# 2 = the target directory for the output.

# remember that this uses C-style array for the args, so ${args[0]} is the 1st arg
# not the program name!

args=("$@")
cd ${args[1]}  || exit

echo "converting OA4MP docs to PDF"

lowriter --headless --convert-to pdf ${args[0]}/qdl/src/main/docs/claim_source_examples.odt              > /dev/null
lowriter --headless --convert-to pdf ${args[0]}/qdl/src/main/docs/creating_claim_sources2.odt            > /dev/null
lowriter --headless --convert-to pdf ${args[0]}/qdl/src/main/docs/oa4mp-modules.odt                      > /dev/null
lowriter --headless --convert-to pdf ${args[0]}/qdl/src/main/docs/oa4mp_running_qdl_scripts.odt          > /dev/null
lowriter --headless --convert-to pdf ${args[0]}/qdl/src/main/docs/qdl_clc_ini.odt                        > /dev/null
lowriter --headless --convert-to pdf ${args[0]}/qdl/src/main/docs/qdl_oa4mp_store_access.odt             > /dev/null
lowriter --headless --convert-to pdf ${args[0]}/qdl/src/main/docs/token_handler_configuration.odt        > /dev/null
lowriter --headless --convert-to pdf ${args[0]}/server-admin/src/main/docs/filestore-migration.odt       > /dev/null
lowriter --headless --convert-to pdf ${args[0]}/server-admin/src/main/docs/rfc7523_intro.odt             > /dev/null
lowriter --headless --convert-to pdf ${args[0]}/server-admin/src/main/docs/jwt-util.odt                  > /dev/null
lowriter --headless --convert-to pdf ${args[0]}/server-admin/src/main/docs/forking_a_flow_quickstart.odt > /dev/null
lowriter --headless --convert-to pdf ${args[0]}/website/src/main/doc/oa2-client.odt                      > /dev/null
lowriter --headless --convert-to pdf ${args[0]}/website/src/main/doc/scopes.odt                          > /dev/null
echo "    ... done with OA4MP docs"
