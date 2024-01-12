# This takes two arguments --
# 1 = the root docs directory of the install where the documents are found
# 2 = the target directory for the output.

# remember that this uses C-style array for the args, so ${args[0]} is the 1st arg
# not the program name!

args=("$@")
cd ${args[1]}  || exit

echo "converting OA4MP docs to PDF"

lowriter --headless --convert-to pdf ${args[0]}/qdl_oa4mp_store_access.odt        > /dev/null
lowriter --headless --convert-to pdf ${args[0]}/creating_claim_sources2.odt       > /dev/null
lowriter --headless --convert-to pdf ${args[0]}/claim_source_examples.odt         > /dev/null
lowriter --headless --convert-to pdf ${args[0]}/token_handler_configuration.odt   > /dev/null
lowriter --headless --convert-to pdf ${args[0]}/qdl_clc_ini.odt                   > /dev/null
echo "done converting OA4MP docs"
