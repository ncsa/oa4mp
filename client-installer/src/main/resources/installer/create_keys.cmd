# A file to create the keys for a new OA4MP install
create_keys -out  ${OA4MP_HOME}etc/keys.jwk -default_id ${JWT_KEY_ID};
create_public_keys -in  ${OA4MP_HOME}etc/keys.jwk -out  ${OA4MP_HOME}etc/public-keys.jwk
set_keys -in ${OA4MP_HOME}etc/keys.jwk;
set_no_output false;
set_verbose true;
list_key_ids;