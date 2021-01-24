When a new version is deployed, here is the testing order
* On localhost
  ** Make SURE VPN to NCSA is working. **
  ** Check local client cfgs to be sure what state they were left in.
  ** Make sure local server is running this configuration: localhost:oa4mp.oa2.mariadb
  ** Note all of these authenticate  to the local tomcat instance.

  -- ashigaru:command.line2
        currently gets basic NCSA claims using the default QDL script
  -- localhost:test/no_cfg
        Has no cfg attribute -- most common case on production
          get_rt, exchange, get_user_info, no cert possible
          at lifetime = 1009 sec.
          rt lifetime = 950400 sec. (11 days)
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

  -- localhost:command.line
        Configured with basic NCSA functor.
  -- localhost:command.line2
         Plain vanilla, no extra claims.
  -- qdl:test0
        This should get a set of standard NCSA claims.
        Currently gets FNAL access token (set DEBUG=true in script before running).
        Check configruation first. Usually it is set to NCSA default and
        a bogus WLCG access token.

* Put on dev, if all worked locally.
  ***
  Copy new cilogon-oa2-cli.jar to /opt/cilogon-oa2/lib and start the CLI. This
  loads the server config and spits out any error messages -- way easier to debug than
  having the server crash on startup.

  See file ~/dev/csd/config/dev-testing.txt for several configurations to test.
  These can't be in this directory since some of the configurations contain passwords.
  ***
  
  Note: Don't have local OA2 server running, since callbacks can get intercepted.
  Local clients
  -- dev:no_cfg
     Has no configuration. Must pass all components
     IDP: Any
  -- dev:command.line
  -- dev:command.line2
  -- dev:syngenta
     NOTE this is a specific version of this for dev!
     -- IDP: GitHub
        Dummy SAML assertions are sent that can get parsed. This triggers the
        introspection machinery for claim sources, so this is a must run test.
        Should get the following claim:
              "member_of": "test_group;test_group_github"
     -- IDP: NCSA
        Should fail, since I am not in the prj_sprout group. Test
        that getcert, exchange, user info and refresh all fail at that point too.
  -- dev:syngenta2
     -- IDP: NCSA IDP
        This is a special configuration where the group name
        in the configuration is cilogon_help not prj_sprout. Everything should work.
        You should be able to get tokens and a cert.
  -- Do demo on dev: https://demo-dev.cilogon.org/cilogon2/ (cilogon:dev.cilogon.org/demo)
       No additional configuration, just basic user claims and a cert.
       IDP: NCSA, UIUC, any

 Clients on other machines
  -- Do serge plain client: https://serge.ncsa.illinois.edu/cilogon-oa2-dev/
       Plain vanilla client, no configuration. Just gets back a cert.
       If this fails, the system is not working at a basic level.
  -- Do serge LSST client: https://serge.ncsa.illinois.edu/lsst-client/ (id ends with 74741)
       ** NOTE: This should return standard NCSA claims and voPersonExternalID must
          be set in the claims or this fails.
       ** NOTE: This is NOT QDL but functor scripting and is a critical regression test.

* Put on test.
  -- Command line client from ashigaru (test:command.line0, id ends with 70530)
  -- Command line client from ashigaru (test:command.line)
  -- Command line client from ashigaru (test:command.line2)
  -- Do surge test client: https://surge.ncsa.illinois.edu/cilogon-oa2-test/
        Plain vanilla, no extra configuration.
  -- Do demo0 client: https://demo0.cilogon.org/cilogon2/ (id ends with demo0)
     This has several modes supported via QDL.
      * login under Goolge - cilogon.org id, should emulate FNAL for me
      * login under Google - ncsa id, basic user claims
      * login under NCSA - returns full set of NCSA credentials
      * Jim B. needs to test with his LIGO credentials
      * Dave at FNAL needs to test with his FNAL credentials
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