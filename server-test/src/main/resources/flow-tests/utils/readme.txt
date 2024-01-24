This directory contains files (in QDL usually) that perform a variety of tasks.

* check_dir - regression test for QDL language changes. Run against

/home/ncsa/dev/ncsa-git/oa4mp/server-admin/src/main/resources/qdl
/home/ncsa/dev/ncsa-git/oa4mp/server-test/src/main/resources/flow-tests

* start.qdl/resume.qdl

starts a bunch of flows on TEST and stashes the results. Run before a new
deploy then right after to check that existing tokens are not somehow
now changed.  See lt-readme.txt

