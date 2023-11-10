This directory contains all the tests for a release. Directories are

 + flow-tests = root
 |
 + cm-tests = Client management tests (localhost only)
 |
 + dev = Auth code flow tests for dev.cilogon.org
 |
 + local = Auth code flow  for localhost
 |    |
 |    + rfc8693 =  Automated tests for exchange, ersatz clients
 |
 + long-term = QDL scripts for long term tests
 |
 + test = Auth code flow tests to test.cilgon.org


 Each directory with Auth code flow tests has an ini file, lt-ids.ini for
 long-term testing.

 Release Testing
 ---------------

 >>> On Localhost <<<
   * run local/all.qdl
   * run cm-tests/all.qdl
   * run local/rfc8693/all.qdl

** Regression test on localhost

   * Downgrade the server to the previous release,
   * run long-term/start.qdl
   * Upgrade the server to the proposed release
   * Run long-term/resume.qdl

 >>> On dev.cilogon.org <<<

Since I have access to dev.cilogon.org and can upgrade it manually, this is
a critical part of the test.

   * Roll the release war
   * Run long-term/start.qdl
   * Upgrade dev
   * Run long-term/resume.qdl
   * Run dev/all.qdl

 >>> On test.cilogon.org <<<

   * Coordinate with sys admin to find when the upgrade happens
   * run long-term/start.qdl before upgrade
   * run long-term/resume.qdl
   * run test/all.qdl