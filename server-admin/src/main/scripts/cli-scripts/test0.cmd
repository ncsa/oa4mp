# This is to test that the CLI now supports command line scripts
echo testing CLI;
use clients;
echo Number of clients: ;
size;
/q;
use admins;
echo number of admins: ;
search >admin_id
       -r .*245.* -rs A;
echo search size: ;
rs size A ;
/q;
/q;

#  -in /home/ncsa/dev/ncsa-git/oa4mp/server-admin/src/main/scripts/cli-scripts/test0.cmd