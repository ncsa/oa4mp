When a new version is deployed, here is the testing order
* On localhost
  ** Make SURE VPN to NCSA is working. **
  ** Check local client cfgs to be sure what state they were left in.
  ** Make sure local server is running this configuration: localhost:oa4mp.oa2.mariadb
  ** Note all of these authenticate  to the local tomcat instance.

  Main testing clients and tests
    -- localhost:command.line
      This has random testing configurations in it, so always check.
      Does NOT have refresh tokens.
      ** Has RFC 8628 = device flow enabled.

  -- localhost:command.line2
     Most basic virtual organization test. Configuration will return JWTs for both access and
     refesh tokens, requiring signatures for generation and verification.
     Also tests code challenge (RFC 7636) machinery.
     set_param -a scope "read: write: x.y:"
     set_param -a code_challenge "N_zjM2czxZIWNar-lWUiuS7-Pacwh-k-L_Akpje6AmY"
     set_param -a code_challenge_method S256
     set_param -t code_verifier "qBdfP8Wmpomgkq6aJwcvZQMHx553RK4P7LAYxmzMAkmo8cM7MlE8ViJSOx38nlHr"
     set_param -t scope "read: write: x.y:"
     set_param -x scope "read:/home/jeff write:/data/jeff/cluster x.y:/abc/def/ghi"

     (The -t option for scopes is set so this works with device flow).
     
     AT, R:
       scopes:
          read:/home/jeff
          write:/data/jeff/cluster
          x.y:/abc/def
       lifetime: 3600000 ms

      TX:
        AT:
          scopes:
            read:/home/jeff
            x.y:/abc/def/ghi
            write:/data/jeff/cluster
          lifetime: same
     * be sure to check get_user_info after refresh token and after TX.
     * Be sure to exchange both an access token and refresh token since these have somewhat difference
       code paths.
         exchange
         exchange -rt

  -- localhost:test/no_cfg
     No configuration of any sort (i.e., cfg is unset, strict scopes etc)
     issue
         clear_all_params -a -t -x
     before hand to remove any state from other client tests. This accepts no additional
     scopes in the request.
     Uses a Derby store for the client, just to make sure that gets tested someplace.
     Most common configuration in production.
     ** Must pass **
       Generic AT with lifetime 1009 sec.
       Generic RT with lifetime 950400 sec.

  -- Test any client for exchange, introspection and revocation.
     This will exchange sets of tokens and introspect on them.
     Look for the "active" attribute in the token. That is what is
     true or false.

     Standard up through get_at. Then
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
        ***************************************************************************
        * Note that this is a critical case for clients since this is available   *
        * to all clients. In particular, clients that are not QDL enabled should  *
        * be able to use this exclusively.                                        *
        ***************************************************************************

        In the token handler document run through the various examples.

        In CLC you need to set the following parameters *before* starting exchange (uri):
        Ex. 1   using the web flow
        set_param -a scope "read: x.y: x.z write:"
        AT:
           scopes:
             read:/home/jeff
             read:/public/lsst/jeff
             x.z
             write:/data/cluster
             x.y:/abc/def
           lifetime: 750 sec.

        Ex 1a - using the device flow, google login
         AT:
           scopes:
              x.z write:/data/cluster
              read:/home/http://cilogon.org/serverA/users/6849
              read:/public/lsst/http://cilogon.org/serverA/users/6849
              x.y:/abc/def,

        set_param -t scope "read: x.y: x.z write:"

        Ex. 2
        set_param -a scope "read:/home/jeff/data x.y: x.z write:/data/cluster/ligo"
        AT:
          scopes:
             read:/home/jeff/data
             x.y:/abc/def
             x.z
             write:/data/cluster/ligo
          lifetime: same as 1

        Ex. 3
        set_param -x scope "read: x.y: x.z write:"
        Do exchange
        AT:
           scopes:
              x.z
           lifetime: same as #1

        Ex. 4
        set_param -x scope "read:/home/jeff/data x.y: x.z write:/data/cluster/ligo"
        do exchange
        AT:
           scopes:
              read:/home/jeff/data
              x.z
              write:/data/cluster/ligo
           lifetime: same as #1
           
        Ex. 5
        set_param -a scope "read:/home/jeff/data x.y: x.z write:/data/cluster/ligo"
        set_param -x scope "read:/home/jeffy x.y:/abc/def/ghi write:/data/cluster1 x.z:/etc/certs"

        access
          AT:
             scopes:
                x.z
                read:/home/jeff/data
                x.y:/abc/def
                write:/data/cluster/ligo
          at lifetime 750 sec
          rt lifetime  3600 sec

        exchange/refresh
          AT:
            scopes:
               x.y:/abc/def/ghi
          same lifetimes

         Example 6:
         set_param -a scope "read:/home/bob"

         AT:
           fails since no scopes can be asserted.

  -- localhost:test/ncsa
     **************************************
     * Second most common configuration.  *
     **************************************
        Test client with the basic default NCSA QDL script.
        Be sure NCSA VPN is active or it will hang forever (many minutes) waiting.
        access:
           at lifetime 1009 sec.
           rt lifetime 950400 sec
           user_info
           CIL-1072 check: check claims expiration 20 minutes
             >> wait a few minutes <<
        refresh:
            same access, rt lifetimes, user_info
            CIL-1072 check: Make sure the new expiration time has been updated
        exchange:
            do both tokens (-rt switch for refresh)
            No id token is returned from here, so no check for its expiration.
        get_cert fails

  -- localhost:scitokens
     test for SciTokens using a user config. Log in with IDP Google and use identity "j g"
     NOTE That this has to have scopes of the form
     read:/home/${sub}
     x.y:/abc/def
     write:/data/${sub}/cluster
     passed in or it will fail with a "no scopes found" exception.

     Safe testing is to request x.y:/abc/def  with

     set_param -a scope "x.y:/abc/def"
     set_param -t scope "x.y:/abc/def"
     set_param -x scope "x.y:/abc/def"

     So that you can use pretty much any IDP

  -- localhost:test/fnal
        Test client that point to main QDL scripts.
        Note that these all use a specific test user in FNAL's LDAP, cilogontest@fnal.gov
        so that it does not matter what identity you log on with, just that you can log on

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
        clear_all_params -a -t -x // if needed.
        set_param -a scope "storage.read:/ wlcg.capabilityset:/duneana wlcg.groups"
        access:
          scopes:
             storage.create:/dune/scratch/users/cilogontest
             storage.read:/dune
          wlcg.groups:
             /dune
             /dune/production
             /fermilab"
          lifetime:750 sec.
         refresh, exchange:
           scopes: same (since no scopes in TX request.)
           lifetime:750 sec.
             (This is set to 1000000000 in the rt_lifetime attribute of the config but
              overridden in the cfg for the client. This tests that works.)

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
        set_param -t scope "compute.modify storage.read:/fermilab/users/cilogontest/public"
        set_param -x scope "compute.cancel foo.bar storage.read:/fermilab/users/cilogontest/public2 storage.create:/fermilab/users/dwd/public2"
          output: single group /fermilab, full capability set

        access
           scopes: compute.modify,compute.create,compute.cancel,compute.read,storage.read:/fermilab/users/cilogontest,storage.create:/fermilab/users/cilogontest
           at lifetime 750 sec
           rt lifetime 750 sec
           which are set in the cfg configuration, overriding the values in the client config proper.

           claims
              should contain: {"wlcg.credkey": "cilogontest"}
           wlcg.groups: [/fermilab]

        refresh
            scopes:
               compute.modify
               storage.read:/fermilab/users/cilogontest/public
            wlcg.groups: [/fermilab]

        exchange
          (has bogus scopes of foo.bar and storage.create:/fermilab/users/dwd/public2)
              scopes:
                 compute.cancel
                 storage.read:/fermilab/users/cilogontest/public2

       Also, do some refreshes, do some exchanges and make sure that the expected scopes
       are always returns faithfully.

      ** OIDC Agent regression test for Dave. His client, oidc-agent simply resends the same scopes at each
      phase. He can't really reconfigure it to do anything else. Load a clean CLC and set

      set_param -a scope "wlcg.capabilityset:/fermilab wlcg.groups:/fermilab"
      set_param -t scope "wlcg.capabilityset:/fermilab wlcg.groups:/fermilab"
      set_param -x scope "wlcg.capabilityset:/fermilab wlcg.groups:/fermilab"
      set_param -t scope "compute.modify storage.read:/fermilab/users/cilogontest/public"
      set_param -x scope "compute.cancel foo.bar storage.read:/fermilab/users/cilogontest/public2 storage.create:/fermilab/users/dwd/public2 wlcg.capabilityset:/fermilab wlcg.groups:/fermilab"

      Use device flow, since that is all Dave is interested in.



  Other localhost testing clients. These exist so various tests can be run.

  -- qdl:test0
        Currently gets FNAL access token (set DEBUG=true in script before running).
        Check configruation first. Usually it is set to NCSA default and
        a bogus WLCG access token.
  -- localhost:test/df --
    *************************
    ** local CILogon test! **
    *************************
     a client for testing the device flow against the CILogon server
     This will require doing the DBService calls manually (that's part of the test).
     In the CLC load the configuration and type
     df

     Approval methods
     A. Use QDL
     Run the QDL scripts with the user_code and the user name. These are in

     /home/ncsa/dev/ncsa-git/cilogon/cilogon2-admin-oauth2/src/main/scripts

     Set the username in the transaction directly (takes place of CILogon backend calls):
     ./set-user.qdl USER_CODE username

     Manually approve the user code:
     ./approve.qdl USER_CODE

     B. Use Terry's scripts
     1. This should respond with a user code, Call it USER_CODE. Paste into this and run it
        from the command line. There are two scripts that do this. Look at them
        to be sure they point to localhost:9443

        bash$ cd ~/dev/ncsa-git/cilogon/cilogon2-admin-oauth2/src/main/scripts
        bash$ test-check-user-code.sh USER_CODE

        That should return with a status of 0 and a summary of the client.
     2. Approve it manually with

        bash$ test-user-code-approved.sh USER_CODE 1

     3. Before you just issue a request for the access token in the CLC, you will need to emulate
        the response from the IDP and set the username for the transaction.
        In the CILogon CLC (talk to the right store, usually cilogon.oa2.mysql), search for the user code:

        search >states -r .*USER_CODE.*
        
        This gets the id (temp token) of the current transaction.

     4. Set the user name there with

        update >username

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
     IDP: NCSA
     Has basic NCSA QDL. This is for testing device flow on CILogon. Execute
     df
     Has refresh lifetime 2 hours
     in the CLC and follow the instructions. Once you've done that you should be
     able to do access, refresh, exchange ahd user_info as per usual. Do them to check
  -- dev:test/functor
     IDP: NCSA
     Critical regression test.
     Has the original NCSA functor configuration on it. Many installs use this.
     Claims isMemberOf is a structure.
     exec phase: access, refresh, exchange
     check claims after each phase to be sure something is returned.
     refresh will update claims, exchange does not.

  -- dev:/test/ncsa_qdl
     Critical regression test.
     IDP: NCSA
     Has standard ncsa/ncsa-default.qdl script with plain vanilla configuration
      -- Should get full claims as list (not a structure)
      -- check that returned id token from refresh still has isMemberOf as flat list.
  
  -- dev:test/fnal
     IDP: Github
     See above for localhost.
     The file fnal/fnal-idtoken.qdl has a DEBUG section that will change users logons to
     another user, strictly for debugging. For me login on Github I can be the test user
     or Dave Dykstra.

     To test as Dave for dunepro (not just fermilab) use this, switch the DEBUG block and set
        set_param -a scope "wlcg.capabilityset:/dunepro wlcg.groups:/dunepro"
        set_param -t scope "storage.create:/dune/data storage.read:/dune"
        set_param -x scope "storage.create:/dune/data storage.read:/dune"

     NOTA BENA: The rtx.qdl script won't run unless you pass in at least scopes or in refresh
                or exchange.

     FNAL Rollback Test:
     To emulate a problem, get an access token, then edit rtx.qdl by adding any illegal
     syntax. Next attempts at token refresh or exchange will fail. Revert back ("fixes problem")
     and the flow should just pick up where it left off.

  -- dev:test/vo1
     IDP: NCSA -- needs an EPPN
     exec phase: ALL
     This will create a WLCG token (barebones) to check if that is signed correctly.
     Note that his has a snippet of QDL code that hard codes the access token subject and scope.
       from the EPPN.
       The main point of this test is that the VO signs
       the tokens with its private key and the verifications work. If the tokens display
       in the CLC, all is good.

TO DO:

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
   (Deprecated since the portal this requires was shutdown.)
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
  -- test:jeff/ligo
       tests VO for ligo with a special command line test client from jeff
       - use GitHub for logon
       - grants subset of all possible scopes (so limited group membership to test that
         it doesn't just always hand back everything).
       The following test for various things like scope reduction

       set_param -a scope "read: write: aud:FOO"
       set_param -r scope "read:/DQSegDB write:/DQSegDB"
       set_param -x scope "read:/DQSegDB/foo write:/DQSegDB read:/frames/bar"
       AT:
         scope:
            read:/frames
            read:/DQSegDB
         lifetime: 21591 sec
       RT:
         scope:
            read:/DQSegDB
         lifetime: same as AT
       TX:
         scope:
            read:/frames/bar
            read:/DQSegDB/foo
         lifetime: same as AT

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

