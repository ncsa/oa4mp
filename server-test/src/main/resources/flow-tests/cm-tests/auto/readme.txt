This directory contains the automated testing for the system.
This is a bumch of managed clients that use RFC7523 as their
authorization method, so the entire suite cann run unattended.

This requires a group of clients that are specialized and
there is a install.qdl script that will install them to your
OA4MP (test) server. Generally you do not want these on
the production server without a good reason.

Client specs : oauth, oidc, ersatz
       types : confidential, public
   overrides : none, client, template, qdl, parameter
Config types : none
               client
               template
               QDL script
               mixed = template and QDL
    AT token : RFC 9068, SciToken, WLCG
    RT token : none, jwt
    ID token : none, basic

ID format
caput:/ [client spec]/type/[other]*/[config type]/?idt=[IDT]&at=[AT]&rt=[RT]&override=[override]

E.g. auto-test:/oauth/conf/template/rfc9068

How to have an OAuth confidential client that tests template overrides, has default ID token, RFC9068 template, RT is JWT

auto-test:/oauth/conf?id=basic&id=mixed&at=qd&at=rfc9068&rt=jwt&overrides=template


--> Have list of templates and ids. The clients are created
from the id and the tests are run as well. This then allows
for looping and creating them in combination.

-----old

The clients are

Basic = nothing, all server defaults
 |
 + client = no other configuration, just client overrides for lifetimes
     |
     + templates = only has templates configured
     |      |
     |      +  t_qdl = has templates that are overridden with QDL
     |
     + qdl = QDL only scripts

Once installed, the tests are in the tests folder and can be run
individually or all of the with the all.qdl script.

== code to parse the uri
   uri. :=  to_uri('auto-test:/oauth/conf?id=basic&id=mixed&at=qdl&at=rfc9068&rt=jwt&overrides=template');
   params.:=[];
   z. := tokenize(tokenize(uri.query,'&'),'=');
   while[v.∈ z.][params.v.0 := ((∃params.v.0)?(params.v.0):[])~v.1;]
   params.
{
 rt: [jwt],
 at: [qdl,rfc9068],
 id: [basic,mixed],
 overrides: [template]
}

   uri. :=  to_uri('auto-test:/oauth/conf?id=basic&id=mixed&at=qdl&at=rfc9068&rt=jwt&overrides=template');
