Long term tests for a service

This emulates the case
of clients with long term active flows that e.g.,
get caught in an upgrade.

Flows are started (with start.qdl) and their state is stashed. Then upgrade the
server and run the resume.qdl command. If there are no errors, then
refreshes and exchanges work with the new server.

The argument is an ini file with the client ids and other information.

(Caveat: pipe the scripts std err someplace since in 5.4 the
underlying client does issues benign warnings.)

=======
The ini file
=======

The syntax is essentially to have section of cfg. stems for the
CLC, plus a default section that has, well, defaults in it.

[default]
save_path := '/home/ncsa/dev/flow-test'; // This is the default.
// typical other defaults then follow, e.g.
      idp := 'NCSA';

If you omit the [default] section, then all system defaults
will be used. In this directory is a sample.ini that can
be boiler-plated.

System defaults
---------------
  save_path := '/home/ncsa/dev/flow-test'; // This is the default.
        idp := 'NCSA';
description := 'long term test of ' + id;
       file := '/home/ncsa/dev/csd/config/client-oa2.xml';
  flow_type := 'uri';
      scope := {Optional string of scopes}
  save_name := {base 32 encoded id}

Here are the entries and their defaults. Only the id is required,
every other item may be specified in the default section and if
missing will be used.

[section_name]
         id := REQUIRED
        idp := 'NCSA';
description := 'long term test of UCSD with read scopes'
       file := '/home/ncsa/dev/csd/config/client-oa2.xml';
  flow_type := 'uri';
      scope := 'read:/x/y read:/p/q/r' // This is a string since ini files do not allow lists here

The scope parameter would be sent on authorization and is a stem of
scopes. The section_name is for you and the contract is to loop over
every section in the file.



=======
Start the flows
=======

./start.qdl path_to_ini

then after a version upgrade on test.cilogon.org, issue

=======
Resume the flows
=======

./resume.qdl path_to_ini

Notes:

 1. refresh token lifetimes will be printed, so don't exceed those.
These are fairly minimal test, aiming for coverage (various tokens) over several
clients.

2. The state files are stashed in /home/ncsa/dev/flow-test.

3. The assumption is that this has long-term refresh tokens, so resume.qdl does
   not update the state. An improvement might be to do that or perhaps have a
   script option that allows for that

4. File names are base 32 encoded.

E.g.:
['ORSXG5B2MNXW23LBNZSC43DJNZSTE','ORSXG5B2NJSWMZRPNRUWO3Y','ORSXG5B2ORSXG5BPMZ2W4Y3UN5ZA','ORSXG5B2ORSXG5BPOVRXGZA']
[test:command.line2,              test:jeff/ligo,           test:test/functor,             test:test/ucsd]
