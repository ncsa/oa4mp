This directory contains the automated testing for the system.
This is a bumch of managed clients that use RFC7523 as their
authorization method, so the entire suite cann run unattended.

This requires a group of clients that are specialized and
there is a install.qdl script that will install them to your
OA4MP (test) server. Generally you do not want these on
the production server without a good reason.

The clients are

Basic = nothing, all server defaults
 |
 + client = no other configuration, just client overrides for lifetimes
     |
     + templates = only has templates configured
     |      |
     |      +  t_qdl = has templates that are overridden with QDL
     |
     + qdl = QDL only scripts

Once installed, the tests are in the tests folder and can be run
individually or all of the with the all.qdl script.