# A file to create the keys for a new OA4MP install
create_keys -out  ${OA4MP_ROOT}etc/keys.jwk -default_id ${JWT_KEY_ID};
set_keys -in ${OA4MP_ROOT}etc/keys.jwk;
set_no_output false;
set_verbose true;
list_key_ids;