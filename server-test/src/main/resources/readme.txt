This is a list of which clients invoke which scripts in testing.
    0 : localhost:/vo1/test0
        access: acl_test/access.qdl
        identity:
    1 : localhost:ccf2
        access: ui-test/at-echo.qdl
        identity:
    2 : localhost:fts
        access: fts/v1/at.qdl
        identity: fts/v1/id-token.qdl
    3 : localhost:fts1
        access: fts/v1/at.qdl
        identity: fts/v1/id-token.qdl
    4 : localhost:p2
        access: ui-test/at-echo.qdl
        identity:
    5 : localhost:p3
        access: ui-test/at-echo.qdl
        identity:
    6 : localhost:test/fnal
        access: fnal/new/at.qdl
        identity:
    7 : localhost:test/igwn
        access: ligo/vo4/at.qdl
        identity:
    8 : localhost:test/jlab
        access: jlab/access.qdl
        identity:
    9 : localhost:test/rfc9068a
        access: process-xas.qdl
        identity: process-xas.qdl
   10 : localhost:test/user_info
        access: ui-test/process.qdl
        identity: ui-test/id-token.qdl

access tokens
       0 : localhost:/vo1/test0     0:acl_test/access.qdl,
       1 : localhost:ccf2           2:,ui-test/at-echo.qdl
       2 : localhost:fts    8:fts/v1/at.qdl,
       3 : localhost:fts1    9:fts/v1/at.qdl,
       4 : localhost:p2    13:ui-test/at-echo.qdl,
       5 : localhost:p3    14:ui-test/at-echo.qdl,
       6 : localhost:test/fnal    19:fnal/new/at.qdl,
       7 : localhost:test/igwn    24:ligo/vo4/at.qdl,
       8 : localhost:test/jlab    25:jlab/access.qdl,
       9 : localhost:test/rfc9068a    31:process-xas.qdl,
      10 : localhost:test/user_info    33:ui-test/process.qdl

ID tokens
       0 : localhost:/vo1/test0         acl_test/id-token.qdl,
       1 : localhost:command.line       oidc/id-token.qdl,
       2 : localhost:fts                fts/v1/id-token.qdl,
       3 : localhost:fts1               fts/v1/id-token.qdl,
       4 : localhost:oa4mp.oa2.mariadb  vfs#/scripts/ncsa/ncsa-default.qdl,
       5 : localhost:test/bnl           bnl/openshift/v1/id-token.qdl,
       6 : localhost:test/fnal          fnal/fnal-idtoken.qdl,
       7 : localhost:test/headers       ui-test/header-test.qdl,
       8 : localhost:test/ncsa          ncsa/ncsa-default.qdl,
       9 : localhost:test/rfc9068a      process-xas.qdl,
      10 : localhost:test/user_info     ui-test/id-token.qdl

refresh tokens
      localhost:test/rfc9068a