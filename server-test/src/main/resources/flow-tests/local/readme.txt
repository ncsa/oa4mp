This directory contains many tests for various flows and other scenarios. It should be run
at least once before any release to ensure proper operation and in particular, no regression.
There are many individual tests, or the one main driver: all.qdl

To invoke, issue

./all.qdl

from the command line. You will be prompted repeatedly (several dozen times) to login
with a spefic IDP and possibly a specific identity (such asunder Google, where there
are often multiple identities possible).

* = critical test
DF= Device Flow
CS = capability set (FNAL only).

Table of tests
Name            Description
-----           -----------
*cil1550        Test for CIL-1550. This sets serialization in OA4MP from QDL and ensures
                that the (new) serialization to JSON operates correctly. Since many
                clients have extremely long lived refresh tokens, they may break if
                this test fails.
                NOTE: This also tests the old functor configuration.
*command_line2  Test for code challenge, basic custom scopes and DF. This configuration
                is inherited by the client in the prototype.qdl test.
                NOTE: This client resides in a VO
ersatz          Test ersatz client. A regular client is provisioned, then the configuration
                for the ersatz client is loaded and the tokens as well as id token
                are all updated.
*file_claims    Test that file claims (in a local file) may be updated on the fly
                i.e. during the test, and the changes are detected. This is the
                test for "liveness" of claim sources which is one of the selling points
                of OA4MP.
fnal-0          Test that FNAL policy with missing CS (capability set) fails
fnal-1          Test that FNAL policy with bad CS (not in their LDAP) fails
fnal-2          Test the FNAL policy with multiple CS fails (only one allowed)
*fnal-3         Test that a legitimate request works
*no_config      Test that most basic client works. This is numerically the most
                common type of client in OA4MP.
*no_qdl         Test that the basic handler configuration (so no QDL) works. Both
                access and refresh tokens are created.
*prototype      Test that inheritance from another client (same as in command_line2)
                works. This loads the client then runs the test for the other client.
*scitokens      Basic Scitoken handler test.
*test_ncsa      The standard NCSA QDL script. All clients that may have users in the NCSA
                will invoke this script to process the users, so this is used all over the
                place.
*test_qdl       Basic test for QDL. This has multiple scripts invoked in a handler, so this
                also tests if they are invoked correctly.

