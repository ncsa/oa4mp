This directory contains QDL scripts used in testing by the automated system.
The Right Way to use this is to add a VFS to the server QDL configuration
that points to this directory. This allows you to simply turn that off

Typical VFS blcok in the configuration is

  <vfs type="pass_through"
       access="rw">
       <root_dir>/home/ncsa/dev/ncsa-git/oa4mp/server-test/src/main/resources/flow-tests</root_dir>
       <scheme><![CDATA[test]]></scheme>
       <mount_point>/</mount_point>
  </vfs>

And add test#/ to your script path.
All the files are accessed under test#/auto/server