package test;


import edu.uiuc.ncsa.myproxy.oa4mp.qdl.scripting.OA2State;
import edu.uiuc.ncsa.qdl.AbstractQDLTester;
import edu.uiuc.ncsa.qdl.TestUtils;
import edu.uiuc.ncsa.qdl.parsing.QDLInterpreter;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/21/16 at  3:44 PM
 */
public class QDLTests extends AbstractQDLTester {
    /**
     * Add the standard OA2 QDL modules to the current test as imports
     *
     * @param script
     */
    protected void addModules(StringBuffer script) {
        addLine(script, "module_load('edu.uiuc.ncsa.oa2.qdl.QDLToolsLoader', 'java');");
        addLine(script, "module_load('edu.uiuc.ncsa.myproxy.oa4mp.qdl.OA2QDLLoader', 'java');");
    }

    protected TestUtils getTestUtils() {
        return TestUtils.newInstance();
    }

    public void testInGroup2() throws Throwable {
        OA2State state = (OA2State) getTestUtils().getNewState();
        StringBuffer script = new StringBuffer();
        addLine(script, "module_load('edu.uiuc.ncsa.myproxy.oa4mp.qdl.OA2QDLLoader', 'java');");
        addLine(script, "module_import('oa2:/qdl/oidc/claims');");
        addLine(script, "groups. := [{'name':'test0','id':123}, {'name':'test1','id':234}, {'name':'test2','id':345}, {'name':'test3','id':456}];");
        addLine(script, "groups2. := ['test0', 'test1', 'test2', 'test3'];");
        addLine(script, "groups3. := ['test0', 'test1', 42, 'test3']; // should fail");
        addLine(script, "groups4. := [{'name':'test0','id':123}, 'test1', 'test2', 'test3']; // should work\n");
        addLine(script, "ok1 := reduce(@&&, in_group2(['test0', 'foo'], groups.)==[true,false]);");
        addLine(script, "ok2 := reduce(@&&, in_group2(['test0', 'foo', 'test2'], groups2.)==[true,false,true]);");
        addLine(script, "ok3 := reduce(@&&, in_group2(['test0', 'foo', 'test2'], groups4.)==[true,false,true]);");
        QDLInterpreter interpreter = new QDLInterpreter(null, state);
        interpreter.execute(script.toString());
        assert getBooleanValue("ok1", state) : "Basic in_group test for structured group list failed";
        assert getBooleanValue("ok2", state) : "Basic in_group test for flat list group list failed";
        assert getBooleanValue("ok3", state) : "Basic in_group test for mixed group list failed";
    }

    public void testInGroup2Fail() throws Throwable {
        OA2State state = (OA2State) getTestUtils().getNewState();
        StringBuffer script = new StringBuffer();
        addLine(script, "module_load('edu.uiuc.ncsa.myproxy.oa4mp.qdl.OA2QDLLoader', 'java');");
        addLine(script, "module_import('oa2:/qdl/oidc/claims');");
        addLine(script, "groups3. := ['test0', 'test1', 42, 'test3']; // should fail");
        addLine(script, "in_group2(['test0', 'foo', 'test2'], groups3.);");
        QDLInterpreter interpreter = new QDLInterpreter(null, state);
        try {
            interpreter.execute(script.toString());
            assert false : "Was able to execute in_group test against bad list";
        } catch (IllegalArgumentException iax) {
            assert true;
        }

    }

    public void testVFSFileClaimSource() throws Throwable {
        OA2State state = (OA2State) getTestUtils().getNewState();
        StringBuffer script = new StringBuffer();
        // tests absolute path, not in server mode.
        /*
        cfg.type :='pass_through';
        cfg.scheme := 'vfs';
        cfg.mount_point := '/test';
        cfg.access := 'rw';
        cfg.root_dir := '/home/ncsa/dev/ncsa-git/oa4mp/oa4mp-server-test-oauth2/src/main/resources';
        vfs_mount(cfg.);
         */
        String testClaimsFile = "vfs2#/test2/test-claims.json";
        addLine(script, "module_load('edu.uiuc.ncsa.myproxy.oa4mp.qdl.OA2QDLLoader', 'java');");
        addLine(script, "module_import('oa2:/qdl/oidc/claims');");
        addLine(script,"vfs_cfg.type :='pass_through';");
        addLine(script,"vfs_cfg.scheme := 'vfs2';");
        addLine(script,"vfs_cfg.mount_point := '/test2';");
        addLine(script,"vfs_cfg.access := 'rw';");
        addLine(script,"vfs_cfg.root_dir := '/home/ncsa/dev/ncsa-git/oa4mp/oa4mp-server-test-oauth2/src/main/resources';");
        addLine(script,"vfs_mount(vfs_cfg.);");  // Now we have a functional VFS with the target file in it.

        addLine(script, "cfg. := new_template('file');");
        addLine(script, "cfg.file_path := '" + testClaimsFile + "';");
        addLine(script, "my_claims. := get_claims(create_source(cfg.), 'jgaynor');");
        addLine(script, "ok_eppn := my_claims.eppn == 'test-eppn@foo.bar';");
        addLine(script, "ok_name := my_claims.isMemberOf.0.name == 'org_ici';");
        addLine(script, "ok_id := my_claims.isMemberOf.0.id == 1282;");
        QDLInterpreter interpreter = new QDLInterpreter(null, state);
        interpreter.execute(script.toString());
        assert getBooleanValue("ok_eppn", state) : "Did not get the correct eppn";
        assert getBooleanValue("ok_name", state) : "Did not get the correct name from the zeroth group";
        assert getBooleanValue("ok_id", state) : "Did not get the correct id from the zeroth group";

    }
    public void testFileClaimSource() throws Throwable {
        OA2State state = (OA2State) getTestUtils().getNewState();
        StringBuffer script = new StringBuffer();
        // tests absolute path, not in server mode.
        String testClaimsFile = "/home/ncsa/dev/ncsa-git/oa4mp/oa4mp-server-test-oauth2/src/main/resources/test-claims.json";
        addLine(script, "module_load('edu.uiuc.ncsa.myproxy.oa4mp.qdl.OA2QDLLoader', 'java');");
        addLine(script, "module_import('oa2:/qdl/oidc/claims');");
        addLine(script, "cfg. := new_template('file');");
        addLine(script, "cfg.file_path := '" + testClaimsFile + "';");
        addLine(script, "my_claims. := get_claims(create_source(cfg.), 'jgaynor');");
        addLine(script, "ok_eppn := my_claims.eppn == 'test-eppn@foo.bar';");
        addLine(script, "ok_name := my_claims.isMemberOf.0.name == 'org_ici';");
        addLine(script, "ok_id := my_claims.isMemberOf.0.id == 1282;");
        QDLInterpreter interpreter = new QDLInterpreter(null, state);
        interpreter.execute(script.toString());
        assert getBooleanValue("ok_eppn", state) : "Did not get the correct eppn";
        assert getBooleanValue("ok_name", state) : "Did not get the correct name from the zeroth group";
        assert getBooleanValue("ok_id", state) : "Did not get the correct id from the zeroth group";
    }

    public void testTemplateSubstitution() throws Throwable {
        OA2State state = (OA2State) getTestUtils().getNewState();
        StringBuffer script = new StringBuffer();
        addLine(script, "module_load('edu.uiuc.ncsa.myproxy.oa4mp.qdl.OA2QDLLoader', 'java');");
        addLine(script, "module_import('oa2:/qdl/oidc/claims');");
        addLine(script, "raw:='storage.read:/bsu/${isMemberOf}/${uid}';");
        addLine(script, "claims.uid ≔ 'bob';");
        addLine(script, "grps.isMemberOf. ≔ ['all','dune'];");
        addLine(script, "ok ≔ reduce(@∧, ['storage.read:/bsu/all/bob','storage.read:/bsu/dune/bob'] ≡ template_substitution(raw, claims., grps.));");
        addLine(script, "ok1 ≔ reduce(@∧, ['a.b/bob','a.c:/all/bob','a.c:/dune/bob'] ≡ template_substitution(['a.b/${uid}', 'a.c:/${isMemberOf}/${uid}'], claims., grps.));");
        QDLInterpreter interpreter = new QDLInterpreter(null, state);
        interpreter.execute(script.toString());
        assert getBooleanValue("ok", state) : "template substitution failed";
        assert getBooleanValue("ok1", state) : "template substitution failed";
    }

    public void testResolveTemplates() throws Throwable {
        OA2State state = (OA2State) getTestUtils().getNewState();
        StringBuffer script = new StringBuffer();
        addLine(script, "module_load('edu.uiuc.ncsa.myproxy.oa4mp.qdl.OA2QDLLoader', 'java');");
        addLine(script, "module_import('oa2:/qdl/oidc/claims');");
        addLine(script, "cs. :=['x.y:/abc/def','p.q:/rst'];");
        addLine(script, "req. := ['x.y:/abc/def/ghi','x.y:/abc/defg', 'p.q:/'];");
        addLine(script, "ok_false ≔ reduce(@∧,resolve_templates(cs., req., false) ≡ ['x.y:/abc/def/ghi']);");
        addLine(script, "ok_true ≔ reduce(@∧,resolve_templates(cs., req., true) ≡ ['p.q:/rst','x.y:/abc/def/ghi']);");
        QDLInterpreter interpreter = new QDLInterpreter(null, state);
        interpreter.execute(script.toString());
        assert getBooleanValue("ok_false", state) : "resolve template failed for non-query";
        assert getBooleanValue("ok_true", state) : "resolve template failed for query";
    }
}
