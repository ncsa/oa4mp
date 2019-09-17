This directory contains scripts that will generate various things for id tokens (ok, JWTs, JSON Web Tokens,
but everyone now calls them ID Tokens so we'll go with that).

Abbreviations
JWT = Java Web Token conforms to RFC
JWK = Java Web Key conforms to RFC

Before running the scripts, you should set the environment by running the set-evn.sh script. Basically you just
need to point it at the jar to invoke. If you got this as a tarball, then it should all just work You only need to
set the environment once in your session.

Read the help for each of the following. You can invoke detailed help by invoking the script with the --help flag.

create_keys file = creates a set of standard RSA keys (both public and private parts) at various strengths. Output is JSON Web Key format.
sign_token [-keyFile file | -url url] -keyid id token = sign an id_token. This prints the result
verify_token [-keyFile file | -url url] token = takes a token and key and verifies the signature.
print_token token = print a token with no verification. 
