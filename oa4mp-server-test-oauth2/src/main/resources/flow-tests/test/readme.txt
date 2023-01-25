Tests for test.cilogon.org

There are tests for checking if an upgrade is compatible with flows.
Flows are started and their state is stashed. This emulates the case
of clients with long term active flows that get caught in an upgrade.

A list of client ids to test is in the script ids.qdl

Start the flows with

./start.qdl

then after a version upgrade on test.cilogon.org, issue

./resume.qdl

Notes:

 1. refresh token lifetimes will be printed, so don't exceed those.
These are fairly minimal test, aiming for coverage (various tokens) over several
clients.

2. The state files are stashed in /home/ncsa/dev/flow-test.

3. The assumption is that this has long-term refresh tokens, so resume.qdl does
   not update the state. An improvement might be to do that or perhaps have a
   script option that allows for that

4. File names are base 32 encoded:
['ORSXG5B2MNXW23LBNZSC43DJNZSTE','ORSXG5B2NJSWMZRPNRUWO3Y','ORSXG5B2ORSXG5BPMZ2W4Y3UN5ZA','ORSXG5B2ORSXG5BPOVRXGZA']
[test:command.line2,              test:jeff/ligo,            test:test/functor,             test:test/ucsd]
