When a new version is deployed, here is the testing order
* On localhost
  ** Make SURE VPN to NCSA is working. **
  ** Check local client cfgs to be sure what state they were left in.
  ** Make sure local server is running this configuration: localhost:oa4mp.oa2.mariadb
  ** Note all of these authenticate  to the local tomcat instance.

  Main testing clients and tests
  -- localhost kubernetes install. This is located in the ~/.kube directory.
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

  -- localhost:test/no_cfg
     No configuration of any sort (i.e., cfg is unset, strict scopes etc)
     Most common configuration in production.
     ** Must pass **
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
        NCSA VPN needs to be active
        Set following in CLC before starting
        set_param -a scope "wlcg.capabilityset:/ storage.create:/ storage.read:/"
        set_param -x scope "wlcg.capabilityset:/ storage.create:/dune/ storage.read:/dune/scratch/users/swhite storage.create:/dune/scratch/users/swhite/temp"

        get_at
           scopes:"storage.create:/dune/scratch/users/swhite storage.read:/dune/"
           at lifetime 550 sec
           rt lifetime 75000sec
           which are set in the cfg configuration, overriding the values in the client config proper.

        claims
           should contain {"wlcg.credkey": "swhite"}

        get_rt
           same lifetimes
           scopes is empty (since initial request had only queries and this request actually returns scopes).

        exchange
           same lifetimes
           scopes = storage.create:/dune/scratch/users/swhite/temp storage.read:/dune/scratch/users/swhite

        Aim is to test passing in various things.

  Other localhost testing clients. These exist so various tests can be run.
  -- localhost:command.line
        Configured with basic NCSA functor.
  -- localhost:command.line2
         Plain vanilla, no extra claims.
  -- qdl:test0
        Currently gets FNAL access token (set DEBUG=true in script before running).
        Check configruation first. Usually it is set to NCSA default and
        a bogus WLCG access token.

  On dev, if all worked locally.
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

  -- dev:test/functor
     Has the original NCSA functor configuration on it. Many installs use this.
     IDP: NCSA only

  -- dev:/test/qdl_ncsa
  
  -- dev:/test/fnal
     IDP: Github
     See above for localhost.

  -- dev:test/vo1
     IDP: any
     This will also create a WLCG token (barebones) to check if that is signed correctly.
       If the CLC works, then it is ok.

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
  -- Command line client from ashigaru (test:command.line0, id ends with 70530)
  -- Command line client from ashigaru (test:command.line)
  -- Command line client from ashigaru (test:command.line2)
  -- Do surge test client: https://surge.ncsa.illinois.edu/cilogon-oa2-test/
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
   -- Farm out testing to others: LSST, LIGO, FNAL

{"tokens": {
    "access":  {
       "audience": "https://wlcg.cern.ch/jwt/v1/access",
         "issuer": "https://access.cilogon.org",
      "lifetime" : 750019
           "type": "wlcg",
      "templates": [ {
           "aud": "https://wlcg.cern.ch/jwt/v1/access",
         "paths":   [
             {"op": "read","path": "/home/${sub}"},
             {"op": "x.y","path": "/abc/def"},
             {"op": "x.z","path": ""},
             {"op": "write","path": "/data/cluster"}
           ]}]
           }
    "refresh":  {
      "audience": "https://wlcg.cern.ch/jwt/refresh",
        "issuer": "https://refresh.cilogon.org",
      "lifetime": 3600000,
          "type": "refresh"
     }
    "identity":  {"type": "identity"}
  }}

