Testing for various clients

This document tells how to set up testing for clients using the command line and debug feature in the
token handler. The pattern is quite easy.

1. Turn on the NCSA VPN if needed, since you need access to NCSA's LDAP server
2. In the IDTokenHandler, set IDP_DEBUG_ON as needed.
3  In the addDebugClaims() method, enable what you want.
4. Start the local OA2 server
5. Start the OA2 command line client
6. load the configuration for the given id
7. Do the interaction and look at the resulting claims

** QDL
IDP_DEBUG_ON: false
   client_id: qdl:/test0
 debugClaims: none
      result: Several claims that include "qdl"

** LSS linking
IDP_DEBUG_ON: true
   client_id: test:/lsst-link
 debugClaims: NCSA IDP | GitHub |  Google | Orcid -- all should resolve the same
      result: voPersonExternalID should be set to the eppn

** LSST onboarding
id:
debug claims: NCSA IDP

** Syngenta
** Must be run in CILogon
client_id: localhost:Syngenta-test


