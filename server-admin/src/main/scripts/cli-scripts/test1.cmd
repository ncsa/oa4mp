# This is to test that the CLI now supports command line scripts
echo testing CLI;
use clients;
size;
// admins;
echo number of admins: ;
size ;
search >admin_id
       -r .*245.* -rs A;
echo search size: ;
rs size A ;
/q;
/q;

#  -batchFile /home/ncsa/dev/ncsa-git/oa4mp/server-admin/src/main/scripts/cli-scripts/test1.cmd