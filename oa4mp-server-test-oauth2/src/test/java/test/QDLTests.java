package test;


import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader.OA2ConfigurationLoader;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.transactions.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.tx.TXRecord;
import edu.uiuc.ncsa.myproxy.oa4mp.qdl.scripting.OA2State;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.RFC8693Constants;
import edu.uiuc.ncsa.qdl.AbstractQDLTester;
import edu.uiuc.ncsa.qdl.TestUtils;
import edu.uiuc.ncsa.qdl.exceptions.QDLExceptionWithTrace;
import edu.uiuc.ncsa.qdl.parsing.QDLInterpreter;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import net.sf.json.JSONObject;

import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamWriter;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.Writer;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;

import static edu.uiuc.ncsa.myproxy.oa4mp.TestUtils.findConfigNode;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/21/20 at  3:44 PM
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
        QDLTestUtils.set_instance(new QDLTestUtils());
        return QDLTestUtils.newInstance();
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
        boolean good = false;
        try {
            interpreter.execute(script.toString());
        } catch (QDLExceptionWithTrace iax) {
            good = iax.getCause() instanceof IllegalArgumentException;
        }
        assert good : "Was able to execute in_group2 test against bad list";

    }

    public void testVFSFileClaimSource() throws Throwable {
        OA2State state = (OA2State) getTestUtils().getNewState();
        StringBuffer script = new StringBuffer();
        // tests absolute path, not in server mode.
        /*
        cfg.type :='pass_through';
        cfg.scheme := 'vfs2';
        cfg.mount_point := '/test2';
        cfg.access := 'rw';
        cfg.root_dir := '/home/ncsa/dev/ncsa-git/oa4mp/oa4mp-server-admin-oauth2/src/main/resources/qdl/ui-test';
        vfs_mount(cfg.);
         */
        String testClaimsFile = "vfs2#/test2/test-claims.json";
        addLine(script, "module_load('edu.uiuc.ncsa.myproxy.oa4mp.qdl.OA2QDLLoader', 'java');");
        addLine(script, "module_import('oa2:/qdl/oidc/claims');");
        addLine(script, "vfs_cfg.type :='pass_through';");
        addLine(script, "vfs_cfg.scheme := 'vfs2';");
        addLine(script, "vfs_cfg.mount_point := '/test2';");
        addLine(script, "vfs_cfg.access := 'rw';");
        addLine(script, "vfs_cfg.root_dir := '/home/ncsa/dev/ncsa-git/oa4mp/oa4mp-server-admin-oauth2/src/main/resources/qdl/ui-test';");
        addLine(script, "vfs_mount(vfs_cfg.);");  // Now we have a functional VFS with the target file in it.

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

    /**
     * This checks that scopes like compute.modify (so just a string, not a uri with
     * path components) is processed. It should not treat such scopes as super scopes
     * @throws Throwable
     */
    public void testResolveTemplates2() throws Throwable {
        OA2State state = (OA2State) getTestUtils().getNewState();
        StringBuffer script = new StringBuffer();
        addLine(script, "module_load('edu.uiuc.ncsa.myproxy.oa4mp.qdl.OA2QDLLoader', 'java');");
        addLine(script, "module_import('oa2:/qdl/oidc/claims');");
        addLine(script, "c.:=['insert:/DQSegDB',\n" +
                "                 'read:/frames',\n" +
                "                 'read:/GraceDB',\n" +
                "                 'compute.create',\n" +
                "                 'compute.create2'\n" +
                "                 ];");
        addLine(script, "    r.:=['openid',\n" +
                "        'profile',\n" +
                "        'email',\n" +
                "        'org.cilogon.userinfo',\n" +
                "        'read:/DQSegDB',\n" +
                "        'write:/DQSegDB',\n" +
                "        'query:/DQSegDB',\n" +
                "        'insert:/DQSegDB',\n" +
                "        'read:/frames',\n" +
                "        'read:/GraceDB',\n" +
                "        'compute.create',\n" +
                "        'compute.cancel',\n" +
                "        'compute.read',\n" +
                "        'compute.modify'\n" +
                "       ];");
        addLine(script, "out. := ['read:/frames','compute.create','read:/GraceDB','insert:/DQSegDB'];"); // expected, note no compute.create2
        addLine(script, "resolved.:= resolve_templates(c., r., false);");
        addLine(script, "size_resolved := size(resolved.);");
        addLine(script, "size_out := size(out.);");
        addLine(script, "size_ok := size_resolved ≡ size_out;");
        addLine(script, "ok ≔ reduce(@∧,out.∈ resolved.);");
        QDLInterpreter interpreter = new QDLInterpreter(null, state);
        interpreter.execute(script.toString());
        assert getBooleanValue("size_ok", state) : "expect  " + getLongValue("size_out", state) + " but got " + getLongValue("size_resolved", state) + " elements";
        assert getBooleanValue("ok", state) : "incorrect result.";
    }
    // next test is a good idea, but was impossible to get running in practice -- just too much
    // configuration needed to bootstrap it. May revisit it later.
/*    public void testATHandler() throws Throwable{
        OA2State state = (OA2State) getTestUtils().getNewState();
        setFakeState(state);
        StringBuffer script = new StringBuffer();
        addLine(script, "module_load('edu.uiuc.ncsa.myproxy.oa4mp.qdl.OA2QDLLoader', 'java');");
        //addLine(script, "module_load('edu.uiuc.ncsa.oa2.qdl.QDLToolsLoader', 'java');");
        addLine(script, "module_import('oa2:/qdl/oidc/claims');");
        addLine(script, "module_import('oa2:/qdl/oidc/token');");
        addLine(script, "z.:=[];");
        addLine(script, "at_init('wlcg',z.);");
        addLine(script, "say(z.);");
        QDLInterpreter interpreter = new QDLInterpreter(null, state);
        interpreter.execute(script.toString());
    }*/

    protected void setFakeState(OA2State oa2State) {
        OA2ServiceTransaction oa2ServiceTransaction = new OA2ServiceTransaction(BasicIdentifier.randomID());
        OA2Client oa2Client = new OA2Client(BasicIdentifier.randomID());
        OA2ConfigurationLoader loader = new OA2ConfigurationLoader(findConfigNode("/home/ncsa/dev/csd/config/server-oa2.xml", "localhost:oa4mp.oa2.mariadb"));
        OA2SE oa2SE = (OA2SE) loader.load();
        oa2State.setOa2se(oa2SE);
        oa2Client.setConfig(new JSONObject());
        oa2ServiceTransaction.setClient(oa2Client);
        oa2State.setTransaction(oa2ServiceTransaction);
    }

    /**
     * Serialization of TXRecord in the QDL state is critical to OA4MP. test that it works here.
     *
     * @throws Exception
     */
    public void testTXecord() throws Throwable {
        // Set it up
        Identifier identifier = BasicIdentifier.randomID();
        Identifier parentID = BasicIdentifier.randomID();
        TXRecord txRecord = new TXRecord(identifier);
        List<String> scopes = new ArrayList<>();
        scopes.add("openid");
        scopes.add("compute.modify");
        scopes.add("org.cilogon.userinfo");
        txRecord.setScopes(scopes);
        long now = System.currentTimeMillis();
        long lifetime = 900 * 1000; // 900 sec
        txRecord.setExpiresAt(now + lifetime);
        txRecord.setIssuedAt(now);
        txRecord.setIssuer("my:issuer");
        txRecord.setParentID(parentID);
        txRecord.setLifetime(lifetime);
        txRecord.setValid(true);
        txRecord.setTokenType(RFC8693Constants.ACCESS_TOKEN_TYPE);
        List<String> audience = new ArrayList<>();
        txRecord.setAudience(audience);
        int n = 3;
        for (int i = 0; i < n; i++) {
            audience.add("aud:" + i);
        }
        List<URI> resources = new ArrayList<>();
        txRecord.setResource(resources);
        for (int i = 0; i < n; i++) {
            resources.add(URI.create("res:" + i));
        }

        // write it
        Writer w = new StringWriter();
        XMLOutputFactory xof = XMLOutputFactory.newInstance();
        XMLStreamWriter xsw = xof.createXMLStreamWriter(w);
        txRecord.toXML(xsw);
        String a = w.toString();
        //System.out.println(XMLUtils.prettyPrint(a));

        // Read it
        StringReader stringReader = new StringReader(a);
        XMLInputFactory xmlif = XMLInputFactory.newInstance();
        XMLEventReader xer = xmlif.createXMLEventReader(stringReader);
        xer.nextEvent(); //start it
        TXRecord txRecord1 = new TXRecord(BasicIdentifier.randomID());
        txRecord1.fromXML(xer);

        assert txRecord1.getLifetime() == txRecord.getLifetime() : "expected " + txRecord.getLifetime() + " but got " + txRecord1.getLifetime();
        assert txRecord1.getIssuedAt() == txRecord.getIssuedAt();
        assert txRecord1.getTokenType().equals(txRecord.getTokenType()) : "expected '" + txRecord.getTokenType() + "' but got '" + txRecord1.getTokenType() + "'";
        assert txRecord1.getParentID().equals(txRecord.getParentID());
        assert txRecord1.getIdentifier().equals(txRecord.getIdentifier());
        assert txRecord1.getExpiresAt() == txRecord.getExpiresAt();
        assert txRecord1.getIssuer().equals(txRecord.getIssuer());
        assert txRecord1.getScopes().size() == txRecord.getScopes().size();
        assert txRecord1.getAudience().size() == txRecord.getAudience().size();
        assert txRecord1.getResource().size() == txRecord.getResource().size();
        checkLists(txRecord.getScopes(), txRecord1.getScopes());
        checkLists(txRecord.getResource(), txRecord1.getResource());
        checkLists(txRecord.getAudience(), txRecord1.getAudience());
        // now for the particulars
    }

    void checkLists(List list1, List list2) {
        for (int i = 0; i < list1.size(); i++) {
            assert list2.contains(list1.get(i));
        }
    }

    String a = "  <tx_record " +
            "id=\"https://test.cilogon.org/oauth2/4d0034722ec53ee4da7825b9b89ddb57?type=accessToken&amp;ts=1646856623934&amp;version=v2.0&amp;lifetime=10800000\" " +
            "expires_at=\"1646856623934\" " +
            "lifetime=\"0\" " +
            "issue_at=\"1646856623934\" " +
            "is_valid=\"false\" " +
            "token_type=\"urn:ietf:params:oauth:token-type:access_token\" " +
            "parent_id=\"https://test.cilogon.org/oauth2/7b8e151e4c6d0f371bd90def043cefbc?type=authzGrant&amp;ts=1646855546449&amp;version=v2.0&amp;lifetime=900000\">\n" +
            "    <scopes>" +
            "      <stem>" +
            "        <entry key=\"0\">\n" +
            "          <string>\n" +
            "            <![CDATA[profile]]>\n" +
            "          </string>\n" +
            "        </entry>\n" +
            // Change the whitespace a bit to make sure that passes too
            "        <entry key=\"1\"><string><![CDATA[email]]>        </string></entry><entry key=\"2\">\n" +
            "          <string>\n" +
            "            <![CDATA[org.cilogon.userinfo]]>\n" +
            "          </string>\n" +
            "        </entry>\n" +
            "        <entry key=\"3\">\n" +
            "          <string>\n" +
            "            <![CDATA[wlcg.capabilityset:/dunepilot]]>\n" +
            "          </string>\n" +
            "        </entry>\n" +
            "        <entry key=\"4\">\n" +
            "          <string>\n" +
            "            <![CDATA[wlcg.groups:/dune]]>\n" +
            "          </string>\n" +
            "        </entry>\n" +
            "        <entry key=\"5\">\n" +
            "          <string>\n" +
            "            <![CDATA[wlcg.groups:/dune/pilot]]>\n" +
            "          </string>\n" +
            "        </entry>\n" +
            "        <entry key=\"6\">\n" +
            "          <string>\n" +
            "            <![CDATA[openid]]>\n" +
            "          </string>\n" +
            "        </entry>\n" +
            "        <entry key=\"7\">\n" +
            "          <string>\n" +
            "            <![CDATA[offline_access]]>\n" +
            "          </string>\n" +
            "        </entry>\n" +
            "      </stem>\n" +
            "    </scopes>\n" +
            "  </tx_record>";

    /**
     * Tests that the older serialized form of the TXRecord is readable. This is critical for
     * any upgrades since there may be very long-lived outstanding TXrecords that need to be read.
     * <br/><br/>CIL-1206 regression test after fix.
     *
     * @throws Throwable
     */
    public void testTXRecordOLD() throws Throwable {
        TXRecord txRecord = new TXRecord(BasicIdentifier.randomID());
        StringReader stringReader = new StringReader(a);
        XMLInputFactory xmlif = XMLInputFactory.newInstance();
        XMLEventReader xer = xmlif.createXMLEventReader(stringReader);
        xer.nextEvent();
        txRecord.fromXML(xer);
        String id = "https://test.cilogon.org/oauth2/4d0034722ec53ee4da7825b9b89ddb57?type=accessToken&ts=1646856623934&version=v2.0&lifetime=10800000";
        String parentID = "https://test.cilogon.org/oauth2/7b8e151e4c6d0f371bd90def043cefbc?type=authzGrant&ts=1646855546449&version=v2.0&lifetime=900000";
        assert txRecord.getTokenType().equals(RFC8693Constants.ACCESS_TOKEN_TYPE);
        assert !txRecord.isValid();
        assert (txRecord.getIdentifier().toString()).equals(id) :
                "expected '" + id  + "' but got '" + txRecord.getIdentifier() + "'";
        assert txRecord.getParentID().toString().equals(parentID);
        assert txRecord.getIssuedAt() == 1646856623934L;
        assert txRecord.getExpiresAt() == 1646856623934L;
        assert txRecord.getLifetime() == 0L;
        assert txRecord.getScopes().contains("profile");
        assert txRecord.getScopes().contains("email");
        assert txRecord.getScopes().contains("org.cilogon.userinfo");
        assert txRecord.getScopes().contains("wlcg.capabilityset:/dunepilot");
        assert txRecord.getScopes().contains("wlcg.groups:/dune");
        assert txRecord.getScopes().contains("wlcg.groups:/dune/pilot");
        assert txRecord.getScopes().contains("offline_access");
        assert txRecord.getScopes().contains("openid");
    }

}
