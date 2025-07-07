# A file to create the keys for a new OA4MP install
echo creating keys in ${OA4MP_HOME}etc/keys.jwk with default ID ${JWT_KEY_ID};
create_keys -out  ${OA4MP_HOME}etc/keys.jwk -default_id ${JWT_KEY_ID};
set_keys -in ${OA4MP_HOME}etc/keys.jwk;
echo Created keys;
set_output_on true;
list_key_ids;