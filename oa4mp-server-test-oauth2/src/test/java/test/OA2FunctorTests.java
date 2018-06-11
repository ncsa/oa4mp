package test;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.*;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.flows.jAccessToken;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.util.JFunctorTest;
import edu.uiuc.ncsa.security.util.functor.JFunctor;
import edu.uiuc.ncsa.security.util.functor.LogicBlock;
import edu.uiuc.ncsa.security.util.functor.LogicBlocks;
import edu.uiuc.ncsa.security.util.functor.logic.*;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims.*;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/1/18 at  11:26 AM
 */
public class OA2FunctorTests extends JFunctorTest {

    @Test
    public void testClaims() throws Exception {
        Map<String, Object> claims = createClaims();
        OA2FunctorFactory factory = new OA2FunctorFactory(claims);
        // create some functors, turn into JSON then have the factory re-create them and do the
        // replacements
        jExists jExists = new jExists();
        jExists.addArg("${" + ISSUER + "}");
        JSONObject rawExists = jExists.toJSON();
        jExists jExists1 = (jExists) factory.fromJSON(rawExists);
        assert jExists1.getArgs().get(0).equals(claims.get(ISSUER));

        jMatch jMatch = new jMatch();
        jMatch.addArg("${" + AUDIENCE + "}");
        jMatch.addArg(claims.get(AUDIENCE).toString());
        jMatch jMatch1 = (jMatch) factory.fromJSON(jMatch.toJSON());
        jMatch1.execute();
        assert jMatch1.getBooleanResult();

        jContains jContains = new jContains();
        jContains.addArg("${" + SUBJECT + "}"); //needle;
        jContains.addArg("$" + SUBJECT + "${" + SUBJECT + "}@fnord.org"); //haystack -- only inner subject should get found
        jContains jContains1 = (jContains) factory.fromJSON(jContains.toJSON());
        jContains1.execute();
        assert jContains1.getBooleanResult();
    }


    @Test
    public void testIncludeClaims() throws Exception {
        Map<String, Object> claims = createClaims();
        jInclude jInclude = new jInclude(claims);
        jInclude.addArg(ISSUER);
        jInclude.addArg(SUBJECT);
        jInclude.execute();
        claims = jInclude.getClaims();
        assert claims.containsKey(ISSUER);
        assert claims.containsKey(SUBJECT);
        assert !claims.containsKey(IDP_CLAIM);
        assert !claims.containsKey(AUDIENCE);
        System.out.println(claims);

    }

    @Test
    public void testExcludeClaims() throws Exception {
        Map<String, Object> claims = createClaims();
        jExclude jExclude = new jExclude(claims);
        jExclude.addArg(ISSUER);
        jExclude.addArg(SUBJECT);
        jExclude.execute();
        claims = jExclude.getClaims();
        assert !claims.containsKey(ISSUER);
        assert !claims.containsKey(SUBJECT);
        assert claims.containsKey(IDP_CLAIM);
        assert claims.containsKey(AUDIENCE);

    }

    @Test
    public void testIsMemberOf() throws Exception {
        Map<String, Object> claims = createClaims();
        jIsMemberOf jIsMemberOf = new jIsMemberOf(claims);
        jIsMemberOf.addArg(GROUP_NAME + "0");
        jIsMemberOf.addArg(GROUP_NAME + "2");
        jIsMemberOf.addArg(GROUP_NAME + "4");
        jIsMemberOf.execute();
        assert jIsMemberOf.getBooleanResult();
        // redo so it fails
        jIsMemberOf = new jIsMemberOf(claims);
        jIsMemberOf.addArg(GROUP_NAME + "0");
        jIsMemberOf.addArg(GROUP_NAME + "2");
        jIsMemberOf.addArg(GROUP_NAME + "4");
        jIsMemberOf.addArg("my-bad-group-name");
        jIsMemberOf.execute();
        assert !jIsMemberOf.getBooleanResult();

    }

    @Test
    public void testAccessToken() throws Exception {
        Map<String, Object> claims = createClaims();
        OA2FunctorFactory ff = new OA2FunctorFactory(claims);
        String rawJson = "{\"$access_token\":[\"$true\"]}";
        JFunctor jf = ff.fromJSON(JSONObject.fromObject(rawJson));
        assert jf instanceof jAccessToken;
        jf.execute();
        assert ((jAccessToken) jf).getBooleanResult();
    }

    public static String IDP_CLAIM = "idp";
    /*
    The start of the names used for the test groups. test-group-0 thru test-group-4 are created.
     */
    public static String GROUP_NAME = "test-group-";

    protected static Map<String, Object> createClaims() {
        HashMap<String, Object> claims = new HashMap<>();
        claims.put(ISSUER, getRandomString());
        claims.put(AUDIENCE, getRandomString());
        claims.put(SUBJECT, getRandomString());
        claims.put(IDP_CLAIM, "https://services.bigstate.edu/grid/" + getRandomString());
        Groups groups = new Groups();
        for (int i = 0; i < 5; i++) {
            GroupElement ge = new GroupElement(GROUP_NAME + i);
            groups.put(ge);
        }
        claims.put(IS_MEMBER_OF, groups);
        return claims;
    }


    @Test
    public void testNestedLB() throws Exception {
        Map<String, Object> claims = createClaims();
        claims.put("eppn", "jgaynor@ncsa.illinois.edu");

        OA2FunctorFactory functorFactory = new OA2FunctorFactory(claims);
        JSONObject jsonObject = new JSONObject();
        JSONArray array = new JSONArray();
        JSONObject ifBlock1 = new JSONObject();

        jContains jContains = new jContains();
        jContains.addArg("foo");
        jContains.addArg("zfoo");
        ifBlock1.put("$if", jContains.toJSON());

        JSONObject ifBlock2 = new JSONObject();
        jEndsWith jEndsWith2 = new jEndsWith();
        jEndsWith2.addArg("${eppn}");
        jEndsWith2.addArg("@ncsa.illinois.edu");

        JSONObject ifBlock3 = new JSONObject();
        jEndsWith jEndsWith3 = new jEndsWith();
        jEndsWith3.addArg("${eppn}");
        jEndsWith3.addArg("@illinois.edu");



        jIf jIf1 = new jIf();
        jContains = new jContains();
        jContains.addArg("foo");
        jContains.addArg("zfoo");
        jIf1.addArg(jContains);

        jThen jThen1 = new jThen();


        jIf jIf2 = new jIf();
        jEndsWith2 = new jEndsWith();
        jEndsWith2.addArg("${eppn}");
        jEndsWith2.addArg("@ncsa.illinois.edu");
        jIf2.addArg(jEndsWith2);
        jThen jThen2 = new jThen();
        jSet jSet2 = new jSet(claims);
        jSet2.addArg("eppn");
        jSet2.addArg("A");
        jThen2.addArg(jSet2);

        jIf jIf3 = new jIf();
        jEndsWith3 = new jEndsWith();
        jEndsWith3.addArg("${eppn}");
        jEndsWith3.addArg("@illinois.edu");
        jIf3.addArg(jEndsWith3);
        jThen jThen3 = new jThen();
        jSet jSet3 = new jSet(claims);
        jSet3.addArg("eppn");
        jSet3.addArg("B");
        jThen3.addArg(jSet3);

        jThen1.addArg(jIf2);
        jThen1.addArg(jIf3);

        LogicBlock lb = new LogicBlock(jIf1, jThen1, null);

        System.out.println("=== nested claims ===");
        System.out.println(lb.toJSON());

    }
   @Test
   public void testLB2() throws Exception{
       String rawJSON = "{\n" +
               "  \"$if\": [\n" +
               "    {\n" +
               "      \"$contains\": [\n" +
               "        \"foo\",\n" +
               "        \"zfoo\"\n" +
               "      ]\n" +
               "    }\n" +
               "  ],\n" +
               "  \"$then\": [\n" +
               "    {\n" +
               "      \"$if\": [{\"$endsWith\": [\"${eppn}\",\"@ncsa.illinois.edu\"]}],\n" +
               "      \"$then\":[{\"$set\":[\"eppn\",\"A\"]}]\n" +
               "    },\n" +
               "    {\n" +
               "      \"$if\": [{\"$endsWith\": [\"${eppn}\",\"@illinois.edu\"]}],\n" +
               "      \"$then\":[{\"$set\":[\"eppn\",\"B\"]}]\n" +
               "    }\n" +
               "  ]\n" +
               "}";
       Map<String, Object> claims = createClaims();
       claims.put("eppn", "jgaynor@ncsa.illinois.edu");
       OA2FunctorFactory functorFactory = new OA2FunctorFactory(claims);


       LogicBlock logicBlock = new LogicBlock(functorFactory, JSONObject.fromObject(rawJSON));
       System.out.println("\n===== nested logic block #2 ===== ");
       System.out.println(logicBlock.toJSON());
       logicBlock.execute();
   }

    /**
     * This tests the logic block creation logic but with claims
     *
     * @return
     * @throws Exception
     */
    @Test
    public void testLBCreation2() throws Exception {
        Map<String, Object> claims = createClaims();
        OA2FunctorFactory functorFactory = new OA2FunctorFactory(claims);
        JSONObject jsonObject = new JSONObject();
        JSONArray array = new JSONArray();
        JSONObject ifBlock = new JSONObject();

        jContains jContains = new jContains();
        jContains.addArg("foo");
        jContains.addArg("zfoo");
        ifBlock.put("$if", jContains.toJSON());

        jSet set = new jSet(claims); // we won't process this, just use it's toJSON to get valid JSON
        set.addArg(AUDIENCE);
        String newAudience = "new-aud-" + getRandomString();
        set.addArg(newAudience);
        System.out.println("jSet=" + set.toJSON());
        ifBlock.put("$then", set.toJSON());
        array.add(ifBlock);
        System.out.println(array.toString(2));

        LogicBlocks<? extends LogicBlock> bloxx = functorFactory.createLogicBlock(array);
        assert bloxx.size() == 1;
        bloxx.execute();
        System.out.println(bloxx.get(0).getResults());

        assert claims.get(AUDIENCE).toString().equals(newAudience);
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

        OA2FunctorFactory functorFactory = new OA2FunctorFactory(claims);
        JSONObject jsonObject = new JSONObject();
        JSONArray array = new JSONArray();
        JSONObject ifBlock = new JSONObject();

        jContains jContains = new jContains();
        jContains.addArg("foo");
        jContains.addArg("zfoo");
        ifBlock.put("$if", jContains.toJSON());

        jSet set = new jSet(claims); // we won't process this, just use it's toJSON to get valid JSON
        set.addArg(AUDIENCE);
        String newAudience = "new-aud-" + getRandomString();
        String targetValue = claims.get("aud") + "--" + newAudience;
        set.addArg("${" + AUDIENCE + "}--" + newAudience);
        JSONArray setCommands = new JSONArray();
        setCommands.add(set.toJSON());
        setCommands.add(set.toJSON());
        setCommands.add(set.toJSON());
        ifBlock.put("$then", setCommands);
        array.add(ifBlock);
        System.out.println(array.toString(2));

        LogicBlocks<? extends LogicBlock> bloxx = functorFactory.createLogicBlock(array);
        assert bloxx.size() == 1;
        bloxx.execute();
        System.out.println("After, claims = " + claims);

        assert claims.get(AUDIENCE).toString().equals(targetValue) : "Should have been \"" + targetValue + "\" and got \"" + claims.get("aud") + "\"";
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
        OA2FunctorFactory functorFactory = new OA2FunctorFactory(claims);
        JSONObject jsonObject = new JSONObject();
        JSONArray array = new JSONArray();
        JSONObject ifBlock = new JSONObject();

        jContains jContains = new jContains();
        jContains.addArg("foo");
        jContains.addArg("zfoo");
        ifBlock.put("$if", jContains.toJSON());

        jSet set = new jSet(claims); // we won't process this, just use it's toJSON to get valid JSON
        set.addArg(AUDIENCE);
        String newAudience = "new-aud-" + getRandomString();
        String targetValue = claims.get("aud") + "--" + newAudience;
        set.addArg("${" + AUDIENCE + "}--" + newAudience);
        ifBlock.put("$then", set.toJSON());
        array.add(ifBlock);
        System.out.println(array.toString(2));

        LogicBlocks<? extends LogicBlock> bloxx = functorFactory.createLogicBlock(array);
        assert bloxx.size() == 1;
        bloxx.execute();
        System.out.println(bloxx.get(0).getResults());

        assert claims.get(AUDIENCE).toString().equals(targetValue) : "Should have been \"" + targetValue + "\" and got \"" + claims.get("aud") + "\"";
    }

    @Test
    public void testCIL() throws Exception {
        // This does not test anything, it lets me create testable code for tinkering
        JSONObject json = new JSONObject();
        jIf ifBlock = new jIf();
        jMatch jMatch = new jMatch();
        jMatch.addArg(IDP_CLAIM);
        jMatch.addArg("https://idp.ncsa.illinois.edu/idp/shibboleth");
        ifBlock.addArg(jMatch);
        jThen jThen = new jThen();
        jSet jSet = new jSet(null);
        jSet.addArg(SUBJECT);
        jSet.addArg("${eppn}");
        jThen.addArg(jSet);
        json.put(ifBlock.getName(), jMatch.toJSON());
        json.put(jThen.getName(), jSet.toJSON());
        System.out.println(json.toString(2));
        System.out.println(ifBlock.toJSON());
        System.out.println(jThen.toJSON());


    }

    /**
     * Tests the set command, in particular that existing claims may be set and
     * that new claims may be created.
     *
     * @throws Exception
     */
    @Test
    public void testSet() throws Exception {

        Map<String, Object> claims = createClaims();
        jSet jSet = new jSet(claims);
        String eppn = "foo@bar.baz";
        jSet.addArg(SUBJECT);
        jSet.addArg(eppn);
        jSet.execute();
        assert claims.get(SUBJECT).equals(eppn);
        // now create a completely new claim and set its value
        jSet = new jSet(claims);
        jSet.addArg("blarg");
        jSet.addArg(eppn);
        jSet.execute();
        assert claims.get("blarg").equals(eppn);

    }

    @Test
    public void testCIL2() throws Exception {
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

    }
}

