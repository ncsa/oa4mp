This directory contains the automated testing for the system.
This is a bunch of managed clients that use RFC7523 as their
authorization method, so the entire suite cann run unattended.

Configuration
-------------
The best way to do this is with a VFS. The VFS on my system (which
goes into the qdl configuration is)

  <vfs type="pass_through"
       access="rw">
       <root_dir>/home/ncsa/dev/ncsa-git/oa4mp/server-test/src/main/resources/flow-tests</root_dir>
       <scheme><![CDATA[test]]></scheme>
       <mount_point>/</mount_point>
  </vfs>

and the corresponding script_path has test#/ added to it. This
permits a really clean separation of paths. Make sure that your
root_dir points to whatever your development environment is.
ALSO, this needs to go into the server configuration as a VFS
if you are testing scripts -- all of the server test scripts for
the client are accessed this way.

Finally, you need to set two extrinsic variables

$$OA4MP_AUTO_TEST_INI - the ini file for testing.
$$OA4MP_CLC_INI - the ini file with all of the clients in it

I set these in a boot_script which is run on startup. You need
this in your client/testing configuration, but NOT in the server
configuration. In particular, the auto test ini file contains passwords
and such so cannot be included in the GitHub tree.

Installing it
------------
This requires a group of clients that are specialized and
there is an install.qdl script that will install them to your
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
