When a new version is deployed, here is the testing order
* On localhost
  ** Make SURE VPN to NCSA is working. **
  ** Check local client cfgs to be sure what state they were left in.
  ** Make sure local server is running this configuration: localhost:oa4mp.oa2.mariadb
  ** Note all of these authenticate  to the local tomcat instance.

  Main testing clients and tests
    -- localhost:command.line
      This has random testing configurations in it, so always check.
      ** Has RFC 8628 = device flow enabled.

  -- localhost:command.line2
     Most basic virtual organization test. Configuration will return JWTs for both access and
     refesh tokens, requiring signatures for generation and verification.
     * be sure to check get_user_info after refresh token and after TX.
     * Be sure to exchange both an access token and refresh token since these have somewhat difference
       code paths.

  -- localhost:test/no_cfg
     No configuration of any sort (i.e., cfg is unset, strict scopes etc)
     Most common configuration in production.
     ** Must pass **

  -- Test any client for exchange, introspection and revocation.
     This will exchange sets of tokens and introspect on them.
     standard up through get_at. Then
     introspect
       > true
     introspect -rt
       > true
     revoke // invalidates access token
       > ok
     introspect // invalidated access token should not be valid
       > false
     exchange
       FAILS (because access token should be invalid and that is used as bearer token)
     exchange -at -x // Have to use refresh token to get back new access token
     introspect
       > true
     exchange -rt // get a new refresh token
     introspect -rt
       > true
     revoke -rt
       > ok
     introspect -rt
       > false
     exchange -rt
       FAILS
     exchange -at
       New access token (since swapping with valid one)
     At this point, the refresh token is invalid and while you can exchange ATs, you cannot ever get another RT
     which is as it should be. If the access token expires, then any attempts to exchange or refresh fail.
  -- localhost:test/no_qdl
        Has basic configuration for tokens, but no scripting
        In CLC you need to set the following parameters *before* starting exchange:

        set_param -a scope "read:/home/jeff x.y: write:"
        set_param -t scope "read:/home/jeff x.y: write:/data/cluster"
        set_param -x scope "read:/home/jeffy x.y:/abc/def/ghi write:/data/cluster1 x.z:/any"

        get_at
          at lifetime 750 sec
          rt lifetime  3600 sec
          at scopes: "read:/home/jeff write:/data/cluster x.y:/abc/def"

        get_rt
          same lifetimes
          scopes: "read:/home/jeff write:/data/cluster"

        exchange
          same at lifetime
          scopes: "x.z:/any x.y:/abc/def/ghi"

        get_user_info
        get_cert "Error: No usable MyProxy service found."

  -- localhost:test/ncsa
        Test client with the basic default NCSA QDL script. Second most common configuration.
        Be sure NCSA VPN is active or it will hang forever (many minutes) waiting.
        get_at
           at_lifetime 1009 sec.
           rt_lifetime 950400 sec
        get_rt, get_user_info, exchange ok
        get_cert fails

  -- localhost:test/fnal
        Test client that point to main QDL scripts.
        Note that these all use a specific test user in FNAL's LDAP, cilogontest@fnal.gov:

        Test #0 -- request with no scopes.
           no scopes in access token (since none requested) => access_denied exception

        Test #1 -- plain, no wlcg capability sets. Requests two storage capabilities, one good one not
        ** INVALID** There used to be entries in LDAP to do this, but they were removed.
                     Keep this test in case they come back, but it will fail until then.
        set_param -a scope "storage.create:/ storage.read:/"
        set_param -x scope "storage.read:/X/public storage.create:/dune/  storage.create:/X/users"

        get_at returns:
                scopes : storage.read:/X,  storage.read:/Y/foo
           at lifetime : 550 sec
           rt lifetime : 750 sec

        exchange returns
        scopes : storage.read:/X/public

        Test #2 -- request non-existent WLCG capability set
        set_param -a scope "wlcg.capabilityset:/fubar "
        Output:
           error="server_error"
           error_description="User does not have access to this capability set. Request denied."

        Test #2.5 -- request multiple WLCG capability set
        set_param -a scope "wlcg.capabilityset:/fermilab wlcg.capabilityset:/dune"
        Output:
           error="access_denied"
           error_description="Multiple capabilities not allowed"


        Test #3 - with wlcg capabilities, no scopes passed in refresh or TX
        Set following in CLC before starting
        clear_all_params if needed.
        set_param -a scope "storage.read:/ wlcg.capabilityset:/duneana wlcg.groups"
        access:
          scopes:
             storage.create:/dune/scratch/users/cilogontest
             storage.read:/dune
          wlcg.groups:
             /dune
             /dune/production
             /fermilab"
          lifetime:3600 sec.
          lifetime:3600 sec.
         refresh, exchange:
           scopes: same (since no scopes in TX request.)
         lifetime: 3600 sec.

        Aim is that the initial set should be resolved to what was passed in.

        Test #4 - with wlcg capabilities for fermilab using test user.
        Load a fresh instance of the CLC (make absolutely sure there is no stale state!!)
        Set following in CLC before starting. Some of the TX scopes are bogus on purpose.
        Do each of the following through the access phase as a quick check

        set_param -a scope "wlcg.capabilityset:/fermilab"
          output: no groups, full capability set for fermilab
        set_param -a scope "wlcg.capabilityset:/fermilab foo:/bar fnord:/baz"
          output: no groups, full capability set for fermilab (bad scopes ignored)
        set_param -a scope "wlcg.groups:/fermilab"
          output: no scopes requested ==> fails
        set_param -a scope "wlcg.groups offline_access"
          output: no scopes requested ==> fails
        set_param -a scope "wlcg.capabilityset:/fermilab wlcg.groups"
          output: all groups, full capability set for fermilab
        set_param -a scope "wlcg.groups:/woof wlcg.capabilityset:/fermilab "
          output: no groups (only one is bogus), full capabilities for fermilab

        This next one is the last one to put in, then add the refresh and transfer scopes
        for testing:

        set_param -a scope "wlcg.capabilityset:/fermilab wlcg.groups:/fermilab"
          output: single group /fermilab, full capability set

        set_param -t scope "compute.modify storage.read:/fermilab/users/cilogontest/public"
        set_param -x scope "compute.cancel foo.bar storage.read:/fermilab/users/cilogontest/public2 storage.create:/fermilab/users/dwd/public2"

        access
           scopes: compute.modify,compute.create,compute.cancel,compute.read,storage.read:/fermilab/users/cilogontest,storage.create:/fermilab/users/cilogontest
           at lifetime 750 sec
           rt lifetime 750 sec
           which are set in the cfg configuration, overriding the values in the client config proper.

           claims
              should contain: {"wlcg.credkey": "cilogontest"}
           wlcg.groups: [/fermilab]

        refresh
            scopes: compute.modify storage.read:/fermilab/users/cilogontest/public
            wlcg.groups: [/fermilab]

        exchange
          (has bogus scopes of foo.bar and storage.create:/fermilab/users/dwd/public2)
              scopes: compute.cancel storage.read:/fermilab/users/cilogontest/public2

       Also, do some refreshes, do some exchanges and make sure that the expected scopes
       are always returns faithfully.


  Other localhost testing clients. These exist so various tests can be run.
  -- localhost:command.line
        Configured with basic NCSA functor.
  -- localhost:command.line2
         Plain vanilla, no extra claims.
  -- qdl:test0
        Currently gets FNAL access token (set DEBUG=true in script before running).
        Check configruation first. Usually it is set to NCSA default and
        a bogus WLCG access token.
  -- localhost:test/df -- a client for testing the device flow against the CILogon server
     This will require doing the DBService calls manually (that's part of the test).
     In the CLC load the configuration and type
     df
     This should respond with a user code, Call it USER_CODE. Paste into this and run it
     from the command line. There are two scripts that do this. Look at them
     to be sure they point to localhost:9443

     bash$ cd ~/dev/ncsa-git/cilogon/cilogon2-admin-oauth2/src/main/scripts
     bash$ test-check-user-code.sh USER_CODE

     That should return with a status of 0 and a summary of the client. Approve it manually
     with

     bash$ test-user-code-approved.sh USER_CODE 1

     Before you just issue a request for the access token in the CLC, you will need to emulate
     the response from the IDP and set the username for the transaction.
     In the CLC, use the

     decode -32 token

     command on the grant in the response. This is the id of the current transaction.
     Set the user name there with

     transactions>update >username

     Does not matter to what.

     *Repeat the above, but cancel the flow using

     bash$ test-user-code-approved.sh USER_CODE 0

     Check in the CLI that the transaction has been removed.

     One last regression test...
     - start flow
     - check use code. Note the scopes
     - attempt to get access token
     - check user code again. Scopes should not change.

  -- Redo this test in toto on dev, if all worked locally, using dev:test/df
  ***
  Copy new cilogon-oa2-cli.jar to /opt/cilogon-oa2/lib and start the CLI. This
  loads the server config and spits out any error messages -- way easier to debug than
  having the server crash on startup.

  See file ~/dev/csd/config/dev-testing.txt for several configurations to test.
  These can't be in this directory since some of the configurations contain passwords.
  ***
  
  Note: Don't have local OA2 server running, since callbacks can get intercepted.
  These testing clients can be run locally or using the CLC on dev.

  -- dev:test/no_cfg
     Has no configuration. Most common case in production. Must pass all components
     IDP: Any

  -- dev:test/df
     Has basic NCSA QDL. This is for testing device flow on CILogon. Execute
     df
     in the CLC and follow the instructions. Once you've done that you should be
     able to do access, refresh, exchange ahd user_info as per usual. Do them to check
  -- dev:test/functor
     Critical regression test.
     Has the original NCSA functor configuration on it. Many installs use this.
     IDP: NCSA only
     exec phase: access, refresh, exchange
     check claims after each phase to be sure something is returned.

  -- dev:/test/ncsa_qdl
     Critical regression test.
     Has standard ncsa/ncsa-default.qdl script with plain vanilla configuration
      -- Should get full claims as list
      -- check that returned id token from refresh and exchange still have isMemberOf as flat list.
  
  -- dev:/test/fnal
     IDP: Github
     See above for localhost.

  -- dev:test/vo1
     IDP: any
     exec phase: ALL
     This will create a WLCG token (barebones) to check if that is signed correctly.
     Note that his has a snippet of QDL code that hard codes the access token subject and scope.
       The main point of this test is that the VO signs
       the tokens with its private key and the verifications work. If the tokens display
       in the CLC, all is good.

TO DO:
  -- dev:/test/ligo
  -- dev:/test/lsst/onboarding
  -- dev:/test/lsst/linking

  -- dev:test/syngenta
     NOTE this is a specific version of this for dev!
     -- IDP: GitHub
        Dummy SAML assertions are sent that can get parsed. This triggers the
        introspection machinery for claim sources, so this is a must run test.
        Should get the following claim:
              "member_of": "test_group;test_group_github"
     -- IDP: NCSA
        Should fail, since I am not in the prj_sprout group. Test
        that getcert, exchange, user info and refresh all fail at that point too.

  -- dev:test/syngenta2
     -- IDP: NCSA IDP
        This is a special configuration where the group name
        in the configuration is cilogon_help not prj_sprout. Everything should work.
        You should be able to get tokens and a cert.
  -- Do demo on dev: https://demo-dev.cilogon.org/cilogon2/ (cilogon:dev.cilogon.org/demo)
       No additional configuration, just basic user claims and a cert.
       IDP: NCSA, UIUC, any
       NOTE: NCSA IDP won't return groups!

 Additional CLCs for me on dev
   -- dev:command.line
   -- dev:command.line2

 Clients talking to dev  from other machines
  -- Do serge plain client: https://serge.ncsa.illinois.edu/cilogon-oa2-dev/
       Plain vanilla client, no configuration. Just gets back a cert.
       If this fails, the system is not working at a basic level.

* Put on test.
-- localhost kubernetes install. This is located in the ~/.kube directory.
   Note that the endpoint here points to test.cilogon.org and is usually not
   available. Contact Dmitry to enable it for testing.
     1. Go to https://portal.nrp-nautilus.io
     2. Select Login (upper right corner)
     3. Log in with NCSA IDP
     4. Now you should see a "Get config" button near the top right hand side. Press it.
     5. Save the config file to the /.kube directory, overwriting the current config file.
     6. At the command line, issue

        ./kubectl get pods

     If it worked, you will get the following error (since I am enrolled in no projects, I just have
     a login):

        Error from server (Forbidden): pods is forbidden: User "http://cilogon.org/serverT/users/173048"
        cannot list resource "pods" in API group "" in the namespace "default"

     Any other message, such as expired token is an error.



  -- Command line client from ashigaru (test:command.line0, id ends with 70530)
  -- Command line client from ashigaru (test:command.line)
  -- Command line client from ashigaru (test:command.line2)

  -- Command line client test:test/no_userinfo
     This is a very primitive client with no refresh and plain vanilla tokens.
     In spite of the name, it does return claims and should work with the
     get_user_info endpoint.
     Basic exchange works, refresh or exchange fail

  -- test:test/ucsd
     This is a public client, very basic, that allows for refresh
     get_user_info is naught else than the barebones subject, audience and issuer.

  -- Do surge test client: https://serge.ncsa.illinois.edu/cilogon-oa2-test/
        Plain vanilla, no extra configuration.
  -- Do demo0 client: https://demo0.cilogon.org/cilogon2/ (id ends with demo0)
     This has several modes supported via QDL.
      * login under Google - cilogon.org id, should emulate FNAL for me
      * login under Google - ncsa id, basic user claims
      * login under NCSA - returns full set of NCSA credentials
      * Jim B. needs to test with his LIGO credentials
      * Dave at FNAL needs to test with his FNAL credentials
  -- Do serge LSST client: https://serge.ncsa.illinois.edu/lsst-client/ (id ends with 74741)
       ** NOTE: This should return standard NCSA claims and voPersonExternalID must
          be set in the claims or this fails.
       ** NOTE: uidNumber must be asserted or this fails.
       ** NOTE: This is NOT QDL but functor scripting and is a critical regression test.
  -- Do https://serge.ncsa.illinois.edu/cilogon-mod/
       Nothing fancy, just a non OA4MP client that returns claims. It should be
       NCSA IDP aware though. (interoperability test).
       N.B. isMemberOf is a flat list of groups, not a JSON structure.
   -- Farm out testing to others: LSST, LIGO, FNAL

