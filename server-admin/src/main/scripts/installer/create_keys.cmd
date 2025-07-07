# A file to create the keys for a new OA4MP install
echo Creating keys in  ${OA4MP_HOME}etc/keys.jwk with default id ${JWT_KEY_ID};
create_keys -out  ${OA4MP_HOME}etc/keys.jwk -default_id ${JWT_KEY_ID};
echo Creating public keys in ${OA4MP_HOME}etc/public-keys.jwk
create_public_keys -in  ${OA4MP_HOME}etc/keys.jwk -out  ${OA4MP_HOME}etc/public-keys.jwk
set_keys -in ${OA4MP_HOME}etc/keys.jwk;
set_output_on true;
echo Created keys:;
list_key_ids;