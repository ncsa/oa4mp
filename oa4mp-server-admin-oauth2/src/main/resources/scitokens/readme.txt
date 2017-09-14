Using the SciTokens command line interface

*Introduction
This is a standalone Java program that allows you to play with various bits of complex tokens. In OAuth, there are (for lack of a better term)
simple tokens and complex tokens. Mostly complex tokens have come about via OIDC and are really Java Web Tokens (JWTs).
A simple token is an opaque string, like an access token
or an authorization grant. This means that "token" is an entirely too overused word and sometimes
the context requires disambiguation. A JWT consists of a payload that is a JSON object as well as perhaps other information, such as
a header and a signature. The classic example of a JWT is the ID token used in OIDC.

*What's it do?

This lets you play with tokens and signatures. You can twiddle claims any which way you want and then generate signed JWTs.
This package contains
- this read me
- the scitokens.jar
- test-keys.jwk, a set of keys that can be used for signing
- claims.json, a set of claims that you may use to test

*Invocation

Invoke this from the command line as a java application:

java -jar scitokens.jar

You will be greeted with the prompt:

scitokens>

* Operations

The supported quick list of operations is as follows:

create_keys -- create a set of signing keys and write them to a file
list_keys -- list the public keys in PEM format (useful for checking with other validation tools)
set_keys -- set the keys to be used automatically for all signing and validation
set_default_id -- set the default id of a key to be used automatically
list_key_ids -- this will list the ids for the keys as well as some metadata about them.

create_token -- take a set of claims in a file and print out the signed token.
print_token -- the last token created with the create_token call.
create_claims -- create a file with a set of claims you input.
parse_claims -- verify that a claims file is parseable and try to give some feedback if it is not.

validate_token -- takes a token (such as from create_token) and verifies the signature against the key.

If you need it, there is help available in the tool by supplying an argument of "--help" E.g.

sciTokens>create_token --help
create_token [-file claims -keys keyfile -keyid id]
              This will take the current keys (uses default) and a file containing a JSON
              format set of claims. It will then sign the claims with the right headers etc.
              and print out the results to the console. Any of the arguments omitted will cause you
              to be prompted. If you have already set the key and keyid these will be used.

Related: set_keys, set_default_id

The way to read this is that the arguments in [] are optional. The related operations should be consulted
if needed. You can even just enter --help at the prompt to get a list of commands:

sciTokens>--help
Here are the commands available:
list_keys
set_default_id
create_token
print_token
create_keys
create_claims
set_keys
parse_claims
validate_token
list_key_ids
To get more information on a command type

command --help
sciTokens>


** A Sample Session creating a set of keys

java -jar scitokens.jar
sciTokens>create_keys
  Give the file path[]:/home/ncsa/temp/scitokens/test-keys.jwk
  create a new set of JSON web keys?[y/n]y
  JSONweb keys written
  Done!

** Session setting keys and creating then validating a token

sciTokens>set_keys /home/ncsa/temp/scitokens/test-keys.jwk
sciTokens>set_default_id 07FD237BE634CB1F4953AE34601E2A18
sciTokens>create_token -file /home/ncsa/temp/scitokens/claims.json
eyJ0eXAiOiJKV1QiLCJraWQiOiIwN0ZEMjM3QkU2MzRDQjFGNDk1M0FFMzQ2MDFFMkExOCIsImFsZyI6IlJTNTEyIn0.eyJzdWIiOjEwMDAsImlzcyI6Imh0dHBzOi8vYXV0aG9yaXphdGlvbi1zZXJ2ZXIuY29tIiwiYXVkIjoiaHR0cHM6Ly9leGFtcGxlLWFwcC5jb20iLCJpYXQiOjE0NzAwMDI3MDMsImV4cCI6MTQ3MDAwOTkwMywic2NvcGUiOiJyZWFkIHdyaXRlIn0.W7zVJIgmeOomEBPaR30Xb8ihOh0SOFtkqSblynh-Bl9RQ3T3_uLV9EgGex8GyDLIzCvWdiNRTjyUgeTiMoWq5gpHo4LNwtwgWos7jJjJjjW2D9Mtm0583tfaidYpehQzUI5yID7y5orMxsMWKxGau4nT77DbwrYpWp0ErJhb4azmHMUpuejH3c1BwecELE6fCUpJt1hi4c4mzGLIbp1--NNBsIyaMBT-8gjEq3SYmrpycJxFE18yUZnTcv7WAPa7XLGUXqHQp6coe4ckoJ7Pf1iWTD58RxE7-Bl5FZ2g45pQFzKu89YQ_bA9mTTUIGBebNWefJ9zv3VOZb9h3y_Zzw
sciTokens>validate_token eyJ0eXAiOiJKV1QiLCJraWQiOiIwN0ZEMjM3QkU2MzRDQjFGNDk1M0FFMzQ2MDFFMkExOCIsImFsZyI6IlJTNTEyIn0.eyJzdWIiOjEwMDAsImlzcyI6Imh0dHBzOi8vYXV0aG9yaXphdGlvbi1zZXJ2ZXIuY29tIiwiYXVkIjoiaHR0cHM6Ly9leGFtcGxlLWFwcC5jb20iLCJpYXQiOjE0NzAwMDI3MDMsImV4cCI6MTQ3MDAwOTkwMywic2NvcGUiOiJyZWFkIHdyaXRlIn0.W7zVJIgmeOomEBPaR30Xb8ihOh0SOFtkqSblynh-Bl9RQ3T3_uLV9EgGex8GyDLIzCvWdiNRTjyUgeTiMoWq5gpHo4LNwtwgWos7jJjJjjW2D9Mtm0583tfaidYpehQzUI5yID7y5orMxsMWKxGau4nT77DbwrYpWp0ErJhb4azmHMUpuejH3c1BwecELE6fCUpJt1hi4c4mzGLIbp1--NNBsIyaMBT-8gjEq3SYmrpycJxFE18yUZnTcv7WAPa7XLGUXqHQp6coe4ckoJ7Pf1iWTD58RxE7-Bl5FZ2g45pQFzKu89YQ_bA9mTTUIGBebNWefJ9zv3VOZb9h3y_Zzw
header={"typ":"JWT","kid":"07FD237BE634CB1F4953AE34601E2A18","alg":"RS512"}
payload={"sub":1000,"iss":"https://authorization-server.com","aud":"https://example-app.com","iat":1470002703,"exp":1470009903,"scope":"read write"}
token valid!
sciTokens>exit
exiting ...

* Useful external links

An example of a self-encoded access token is here: https://www.oauth.com/oauth2-servers/access-tokens/self-encoded-access-tokens/

Another tool to check token validity is here: https://jwt.io/
For this last tool, you will put the encoded token (output from create_token) into the form and the corresponding public key
(output in PEM format from list_keys).