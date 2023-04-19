This directory contains scripts and testing JSON requests for doing anonymous
client creations. That means that for POST

- no admin client is needed
- the server must be configured to do this explicitly
- the client is not approved by default
- server policies (such as a template) are applied.

IF RFC 7592 is enabled, then the client can get itself, using its id and
password. If RFC 7592 is not enabled, requests are rejected

** No deletes or updates are allowed for any client. These must be done
   using an admin client to preserve the trust relations.

