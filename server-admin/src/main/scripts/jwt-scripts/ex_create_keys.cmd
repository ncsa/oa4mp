# This sample batch file will create a set of keys and print them to the terminal
#

create_keys -out /tmp/test_keys.jwk;

# Creates a set of keys in the tmp directory. 
echo Done writing full set of keys;
create_keys
     -in /tmp/test_keys.jwk
     -public
      -out /tmp/pub_test_keys.jwk;

# This takes the full set of keys in jwk format specified by the -in switch, generates the public
# keys and writes them to the file specified in the -out switch

echo Done writing public keys;