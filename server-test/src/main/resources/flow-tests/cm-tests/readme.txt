This directory contains a slew of tests for the client management API.

These are the server configs for tests

cm_local - Jeff's local box
  cm_dev - the DEV box
 cm_test - test TEST box

Each of which has a specific configuration it will use. Invoke this script like

./all.qdl - runs local tests
./all.qdl config -- runs the given suite against the configuration.

Remember: At the end of the test, cm-cleanup will run and remove all of the custom
          created test clients for this admin. This should therefore be
          considered a destructive test so the admin clients should ONLY be used for
          testing!