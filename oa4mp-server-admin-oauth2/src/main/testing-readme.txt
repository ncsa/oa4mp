When a new version is deployed, here is the testing order
* On localhost
  ** Make SURE VPN to NCSA is working. **
     Check local client cfgs to be sure what state they were left in.
  -- Run command line client #0 (ashigaru:command.line2)
        currently gets basic NCSA claims
  -- Run command line client #1 (localhost:command.line)
  -- Run command line client #2 (localhost:command.line2)
         Plain vanilla, no extra claims.
  -- Start local QDL-aware client on ashigaru (qdl:test0)
        This should get a set of standard NCSA claims.
        Currently gets FNAL access token (set DEBUG=true in script before running).
  -- Run local OA2 server. (localhost:oa4mp.oa2.mariadb)
        Check configruation first. Usually it is set to NCSA default and
        a bogus WLCG access token.

* Put on dev.
  -- Use command line client #1 from ashigaru (dev:command.line)
  -- Use command line client #2 from ashigaru (dev:command.line2)
  -- Do demo on dev: https://demo-dev.cilogon.org/cilogon2/ (cilogon:dev.cilogon.org/demo)
       No additional configuration, just basic user claims and a cert.
  -- Do surge plain client: https://surge.ncsa.illinois.edu/cilogon-oa2-dev/
       Plain vanilla client, no configuration. Just gets back a cert.
       If this fails, the system is not working at a basic level.
  -- Do surge LSST client: https://surge.ncsa.illinois.edu/lsst-client/ (id ends with 74741)
       ** NOTE: This should return standard NCSA claims and voPersonExternalID must
          be set in the claims or this fails.
       ** NOTE: This is NOT QDL but functor scripting and is a critical regression test.

* Put on test.
  -- Command line client from ashigaru (test:command.line, id ends with 70530)
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

