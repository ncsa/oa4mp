package test;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.CAFunctorFactory;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.jExclude;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.jInclude;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.jSet;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.flows.jAccessToken;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.ClaimsProcessor;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Client;
import edu.uiuc.ncsa.security.util.JFunctorTest;
import edu.uiuc.ncsa.security.util.functor.JFunctor;
import edu.uiuc.ncsa.security.util.functor.LogicBlock;
import edu.uiuc.ncsa.security.util.functor.logic.*;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.junit.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/1/18 at  11:26 AM
 */
public class FunctorTests extends JFunctorTest {

    @Test
    public void testClaims() throws Exception {
        Map<String, Object> claims = createClaims();
        CAFunctorFactory factory = new CAFunctorFactory(claims);
        // create some functors, turn into JSON then have the factory re-create them and do the
        // replacements
        jExists jExists = new jExists();
        jExists.addArg("${issuer}");
        JSONObject rawExists = jExists.toJSON();
        jExists jExists1 = (jExists) factory.fromJSON(rawExists);
        assert jExists1.getArgs().get(0).equals(claims.get("issuer"));

        jMatch jMatch = new jMatch();
        jMatch.addArg("${aud}");
        jMatch.addArg(claims.get("aud").toString());
        jMatch jMatch1 = (jMatch) factory.fromJSON(jMatch.toJSON());
        jMatch1.execute();
        assert jMatch1.getBooleanResult();

        jContains jContains = new jContains();
        jContains.addArg("${sub}"); //needle;
        jContains.addArg("$sub${sub}@fnord.org"); //haystack
        jContains jContains1 = (jContains) factory.fromJSON(jContains.toJSON());
        jContains1.execute();
        assert jContains1.getBooleanResult();
    }


    @Test
    public void testIncludeClaims() throws Exception {
        Map<String, Object> claims = createClaims();
        jInclude jInclude = new jInclude(claims);
        jInclude.addArg("issuer");
        jInclude.addArg("sub");
        jInclude.execute();
        claims = jInclude.getClaims();
        assert claims.containsKey("issuer");
        assert claims.containsKey("sub");
        assert !claims.containsKey("idp");
        assert !claims.containsKey("aud");
        System.out.println(claims);

    }

    @Test
    public void testExcludeClaims() throws Exception {
        Map<String, Object> claims = createClaims();
        jExclude jExclude = new jExclude(claims);
        jExclude.addArg("issuer");
        jExclude.addArg("sub");
        jExclude.execute();
        claims = jExclude.getClaims();
        assert !claims.containsKey("issuer");
        assert !claims.containsKey("sub");
        assert claims.containsKey("idp");
        assert claims.containsKey("aud");

    }

    @Test
    public void testAccessToken() throws Exception{
        Map<String, Object> claims = createClaims();
        CAFunctorFactory ff = new CAFunctorFactory(claims);
        String rawJson = "{\"$access_token\":[\"$true\"]}";
        JFunctor jf = ff.fromJSON(JSONObject.fromObject(rawJson));
        assert jf instanceof jAccessToken;
        jf.execute();
        assert ((jAccessToken) jf).getBooleanResult();
    }

    protected Map<String, Object> createClaims() {
        HashMap<String, Object> claims = new HashMap<>();
        claims.put("issuer", getRandomString());
        claims.put("aud", getRandomString());
        claims.put("sub", getRandomString());
        claims.put("idp", "https://services.bigstate.edu/grid/" + getRandomString());
        return claims;
    }

    /**
     * This tests the logic block creation logic.
     *
     * @return
     * @throws Exception
     */
    @Test
    public void testLBCreation2() throws Exception {
        Map<String, Object> claims = createClaims();
        CAFunctorFactory functorFactory = new CAFunctorFactory(claims);
        JSONObject jsonObject = new JSONObject();
        JSONArray array = new JSONArray();
        JSONObject ifBlock = new JSONObject();

        jContains jContains = new jContains();
        jContains.addArg("foo");
        jContains.addArg("zfoo");
        ifBlock.put("$if", jContains.toJSON());

        jSet set = new jSet(claims); // we won't process this, just use it's toJSON to get valid JSON
        set.addArg("aud");
        String newAudience = "new-aud-" + getRandomString();
        set.addArg(newAudience);
        System.out.println("jSet=" + set.toJSON());
        ifBlock.put("$then", set.toJSON());
        array.add(ifBlock);
        System.out.println(array.toString(2));

        List<LogicBlock> bloxx = functorFactory.createLogicBlock(array);
        assert bloxx.size() == 1;
        bloxx.get(0).execute();
        System.out.println(bloxx.get(0).getResults());

        assert claims.get("aud").toString().equals(newAudience);
    }

    /**
     * When a claims value is accessed in a set command, the old claims value is accessed.
     * makes it hard to change a value and use the new one, but does allow for integrity of the
     * claims object.  Note that since the values are replaced in the factory, they should remain stable
     * if the value is reset several times, such as here.
     *
     * @throws Exception
     */
    @Test
    public void testLBClaimsIntegrity() throws Exception {
        Map<String, Object> claims = createClaims();
        System.out.println("Before, claims = " + claims);

        CAFunctorFactory functorFactory = new CAFunctorFactory(claims);
        JSONObject jsonObject = new JSONObject();
        JSONArray array = new JSONArray();
        JSONObject ifBlock = new JSONObject();

        jContains jContains = new jContains();
        jContains.addArg("foo");
        jContains.addArg("zfoo");
        ifBlock.put("$if", jContains.toJSON());

        jSet set = new jSet(claims); // we won't process this, just use it's toJSON to get valid JSON
        set.addArg("aud");
        String newAudience = "new-aud-" + getRandomString();
        String targetValue = claims.get("aud") + "--" + newAudience;
        set.addArg("${aud}--" + newAudience);
        JSONArray setCommands = new JSONArray();
        setCommands.add(set.toJSON());
        setCommands.add(set.toJSON());
        setCommands.add(set.toJSON());
        ifBlock.put("$then", setCommands);
        array.add(ifBlock);
        System.out.println(array.toString(2));

        List<LogicBlock> bloxx = functorFactory.createLogicBlock(array);
        assert bloxx.size() == 1;
        bloxx.get(0).execute();
        System.out.println("After, claims = " + claims);

        assert claims.get("aud").toString().equals(targetValue) : "Should have been \"" + targetValue + "\" and got \"" + claims.get("aud") + "\"";
    }

    /**
     * This test creates and array of set command and executes them. This tests that the machinery for doing an
     * in situ replacement works.
     *
     * @throws Exception
     */
    @Test
    public void testLBClaimsReplacement() throws Exception {
        Map<String, Object> claims = createClaims();
        CAFunctorFactory functorFactory = new CAFunctorFactory(claims);
        JSONObject jsonObject = new JSONObject();
        JSONArray array = new JSONArray();
        JSONObject ifBlock = new JSONObject();

        jContains jContains = new jContains();
        jContains.addArg("foo");
        jContains.addArg("zfoo");
        ifBlock.put("$if", jContains.toJSON());

        jSet set = new jSet(claims); // we won't process this, just use it's toJSON to get valid JSON
        set.addArg("aud");
        String newAudience = "new-aud-" + getRandomString();
        String targetValue = claims.get("aud") + "--" + newAudience;
        set.addArg("${aud}--" + newAudience);
        ifBlock.put("$then", set.toJSON());
        array.add(ifBlock);
        System.out.println(array.toString(2));

        List<LogicBlock> bloxx = functorFactory.createLogicBlock(array);
        assert bloxx.size() == 1;
        bloxx.get(0).execute();
        System.out.println(bloxx.get(0).getResults());

        assert claims.get("aud").toString().equals(targetValue) : "Should have been \"" + targetValue + "\" and got \"" + claims.get("aud") + "\"";
    }

    @Test
    public void testCIL() throws Exception {
        // This does nt test anything, it lets me create testable code for tinkering
        JSONObject json = new JSONObject();
        jIf ifBlock = new jIf();
        jMatch jMatch = new jMatch();
        jMatch.addArg("idp ");
        jMatch.addArg("https://idp.ncsa.illinois.edu/idp/shibboleth");
        ifBlock.addArg(jMatch);
        jThen jThen = new jThen();
        jSet jSet = new jSet(null);
        jSet.addArg("sub");
        jSet.addArg("${eppn}");
        jThen.addArg(jSet);
        json.put(ifBlock.getName(), jMatch.toJSON());
        json.put(jThen.getName(), jSet.toJSON());
        System.out.println(json.toString(2));
        System.out.println(ifBlock.toJSON());
        System.out.println(jThen.toJSON());



    }



    @Test
    public void testCIL2() throws Exception{
        HashMap<String, Object> claims2 = new HashMap<>();
        claims2.put("sub", "http://cilogon.org/serverT/users/173048");
        claims2.put("idp_name", "National Center for Supercomputing Applications");
        claims2.put("idp", "https://idp.ncsa.illinois.edu/idp/shibboleth");
        claims2.put("mail", "gaynor@illinois.edu");
        claims2.put("affiliation", "staff@ncsa.illinois.edu;employee@ncsa.illinois.edu;member@ncsa.illinois.edu");
        claims2.put("eppn", "jgaynor@ncsa.illinois.edu");
        claims2.put("cert_subject_dn", "/DC=org/DC=cilogon/C=US/O=National Center for Supercomputing Applications/CN=Jeffrey Gaynor T173053 email=gaynor@illinois.edu");
        claims2.put("name", "Jeffrey Gaynor");
        claims2.put("isMemberOf", "[\"cn=jira-users,ou=Groups,dc=ncsa,dc=illinois,dc=edu\",\"cn=org_all_groups,ou=Groups,dc=ncsa,dc=illinois,dc=edu\",\"cn=all_ncsa_employe,ou=Groups,dc=ncsa,dc=illinois,dc=edu\",\"cn=grp_jira_users,ou=Groups,dc=ncsa,dc=illinois,dc=edu\",\"cn=all_users,ou=Groups,dc=ncsa,dc=illinois,dc=edu\",\"cn=grp_bldg_ncsa,ou=Groups,dc=ncsa,dc=illinois,dc=edu\",\"cn=grp_bldg_both,ou=Groups,dc=ncsa,dc=illinois,dc=edu\",\"cn=org_cisr,ou=Groups,dc=ncsa,dc=illinois,dc=edu\",\"cn=org_ici,ou=Groups,dc=ncsa,dc=illinois,dc=edu\",\"cn=org_csd,ou=Groups,dc=ncsa,dc=illinois,dc=edu\",\"cn=prj_cerb_users,ou=Groups,dc=ncsa,dc=illinois,dc=edu\",\"cn=iam_sec_testing,ou=Groups,dc=ncsa,dc=illinois,dc=edu\",\"cn=all_building,ou=Groups,dc=ncsa,dc=illinois,dc=edu\"]");
        claims2.put("given_name", "Jeffrey");
        claims2.put("family_name", "Gaynor");
        claims2.put("email", "gaynor@illinois.edu}");

        String rawConfig = "{\"config\":\"testforurgeclient\",\"id_token\":{\"$if\":{\"$match\":[\"${idp}\",\"https://idp.ncsa.illinois.edu/idp/shibboleth\"]},\"$then\":{\"$set\":[\"sub\",\"${eppn}\"]}}}";
        OA2Client client = new OA2Client(BasicIdentifier.newID("test:client:42"));
        client.setConfig(JSONObject.fromObject(rawConfig));
        ClaimsProcessor ch = new ClaimsProcessor(client.getClaimsConfig());
        DebugUtil.setIsEnabled(true);
        Map<String, Object> claims3 = ch.process(claims2);
        System.out.println("\n*** CIL2 claims handler test");
        System.out.println(claims3);
        System.out.println("\n*** done. Returned claims:");
        assert claims3.get("sub").equals(claims2.get("eppn"));
    }
}

