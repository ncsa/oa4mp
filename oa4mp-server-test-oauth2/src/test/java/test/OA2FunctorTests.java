package test;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.*;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.flows.jAccessToken;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.state.OA2ClientConfiguration;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.state.OA2ClientConfigurationFactory;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.state.OA2ClientConfigurationUtil;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.util.JFunctorTest;
import edu.uiuc.ncsa.security.util.functor.*;
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
        assert reTestIt(jMatch1, factory).getBooleanResult();

        jContains jContains = new jContains();
        jContains.addArg("${" + SUBJECT + "}"); //needle;
        jContains.addArg("$" + SUBJECT + "${" + SUBJECT + "}@fnord.org"); //haystack -- only inner subject should get found
        jContains jContains1 = (jContains) factory.fromJSON(jContains.toJSON());
        jContains1.execute();
        assert jContains1.getBooleanResult();
        assert reTestIt(jContains1, factory).getBooleanResult();
    }

    @Test
      public void testRenameClaim() throws Exception {
        Map<String, Object> claims = createClaims();
        String value = (String) claims.get(AUDIENCE);
        jRename rename = new jRename(claims);
        String newName = "foo";
        rename.addArg(AUDIENCE);
        rename.addArg(newName);
        OA2FunctorFactory ff = new OA2FunctorFactory(claims);
        rename = (jRename) reTestIt(rename, ff); // also test that the factory knows about this.

        assert !rename.getClaims().containsKey(AUDIENCE);
        assert rename.getClaims().containsKey(newName);
        assert rename.getClaims().get(newName).equals(value);
    }

    @Test
    public void testIncludeClaims() throws Exception {
        Map<String, Object> claims = createClaims();
        // Make sure the two sets of claims are independent so the tests don't interfere with each other,
        Map<String, Object> claims2 = new HashMap<>();
        claims2.putAll(claims);

        OA2FunctorFactory ff = new OA2FunctorFactory(claims2);
        jInclude jInclude = new jInclude(claims);
        jInclude.addArg(ISSUER);
        jInclude.addArg(SUBJECT);
        jInclude.execute();
        jInclude x = (jInclude) reTestIt(jInclude, ff);

        claims = jInclude.getClaims();
        assert claims.containsKey(ISSUER);
        assert claims.containsKey(SUBJECT);
        assert !claims.containsKey(IDP_CLAIM);
        assert !claims.containsKey(AUDIENCE);

        claims = x.getClaims();
        assert claims.containsKey(ISSUER);
        assert claims.containsKey(SUBJECT);
        assert !claims.containsKey(IDP_CLAIM);
        assert !claims.containsKey(AUDIENCE);


    }

    @Test
    public void testExcludeClaims() throws Exception {
        Map<String, Object> claims = createClaims();
        Map<String, Object> claims2 = new HashMap<>();
        claims2.putAll(claims);

        OA2FunctorFactory ff = new OA2FunctorFactory(claims2);
        jExclude jExclude = new jExclude(claims);
        jExclude.addArg(ISSUER);
        jExclude.addArg(SUBJECT);
        jExclude.execute();
        jExclude x = (jExclude) reTestIt(jExclude, ff);

        claims = jExclude.getClaims();
        assert !claims.containsKey(ISSUER);
        assert !claims.containsKey(SUBJECT);
        assert claims.containsKey(IDP_CLAIM);
        assert claims.containsKey(AUDIENCE);


        claims = x.getClaims();
        assert !claims.containsKey(ISSUER);
        assert !claims.containsKey(SUBJECT);
        assert claims.containsKey(IDP_CLAIM);
        assert claims.containsKey(AUDIENCE);

    }

    @Test
    public void testIsMemberOf() throws Exception {
        Map<String, Object> claims = createClaims();
        OA2FunctorFactory ff = new OA2FunctorFactory(claims);
        jIsMemberOf jIsMemberOf = new jIsMemberOf(claims);
        jIsMemberOf.addArg(GROUP_NAME + "0");
        jIsMemberOf.addArg(GROUP_NAME + "2");
        jIsMemberOf.addArg(GROUP_NAME + "4");
        jIsMemberOf.execute();
        assert jIsMemberOf.getBooleanResult();
        assert reTestIt(jIsMemberOf, ff).getBooleanResult();
        // redo so it fails
        jIsMemberOf = new jIsMemberOf(claims);
        jIsMemberOf.addArg(GROUP_NAME + "0");
        jIsMemberOf.addArg(GROUP_NAME + "2");
        jIsMemberOf.addArg(GROUP_NAME + "4");
        jIsMemberOf.addArg("my-bad-group-name");
        jIsMemberOf.execute();

        assert !jIsMemberOf.getBooleanResult();
        assert !reTestIt(jIsMemberOf, ff).getBooleanResult();
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

    /**
     * A basic set of claims, issuer, audience, subject, idp and a group with elements test-group-0,test-group-1,...,,
     * test-group-4.
     * @return
     */
    protected static JSONObject createClaims() {
        JSONObject claims = new JSONObject();
        claims.put(ISSUER, getRandomString());
        claims.put(AUDIENCE, getRandomString());
        claims.put(SUBJECT, getRandomString());
        claims.put(IDP_CLAIM, "https://services.bigstate.edu/grid/" + getRandomString());
        Groups groups = new Groups();
        for (int i = 0; i < 5; i++) {
            GroupElement ge = new GroupElement(GROUP_NAME + i);
            groups.put(ge);
        }
        String rawGroups = groups.toJSON().toString();
        claims.put(IS_MEMBER_OF, rawGroups);
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

        LogicBlock lb = new LogicBlock(functorFactory, jIf1, jThen1, null);


    }

    @Test
    public void testLB2() throws Exception {
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
        ifBlock.put("$then", set.toJSON());
        array.add(ifBlock);
         JSONObject j = new JSONObject();
        j.put(FunctorTypeImpl.OR.getValue(), array);
        LogicBlocks<? extends LogicBlock> bloxx = functorFactory.createLogicBlock(j);
        assert bloxx instanceof ORLogicBlocks;
        assert bloxx.size() == 1;
        bloxx.execute();

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
        JSONObject j = new JSONObject();
        j.put(FunctorTypeImpl.XOR.getValue(), array);
        LogicBlocks<? extends LogicBlock> bloxx = functorFactory.createLogicBlock(j);
        assert bloxx instanceof XORLogicBlocks;
        assert bloxx.size() == 1;
        bloxx.execute();
        assert (boolean) bloxx.getResult();

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
        JSONObject j = new JSONObject();
        j.put(FunctorTypeImpl.AND.getValue(), array);
        LogicBlocks<? extends LogicBlock> bloxx = functorFactory.createLogicBlock(j);
        assert bloxx instanceof ANDLogicBlocks;
        assert bloxx.size() == 1;
        bloxx.execute();

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


    }

    @Test
    public void testHasClaim() throws Exception {
        Map<String, Object> claims = createClaims();
        OA2FunctorFactory ff = new OA2FunctorFactory(claims);
        String testClaim = IDP_CLAIM;
        jHasClaim hasClaim = new jHasClaim(claims);
        hasClaim.addArg(IDP_CLAIM);
        hasClaim.execute();
        assert hasClaim.getBooleanResult();
        assert reTestIt(hasClaim, ff).getBooleanResult();
        hasClaim.reset();
        hasClaim.addArg("foo");
        hasClaim.execute();
        assert !reTestIt(hasClaim, ff).getBooleanResult();
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
        Map<String, Object> claims2 = new HashMap<>();
        claims2.putAll(claims);

        OA2FunctorFactory ff = new OA2FunctorFactory(claims2);
        jSet jSet = new jSet(claims);
        String eppn = "foo@bar.baz";
        jSet.addArg(SUBJECT);
        jSet.addArg(eppn);
        jSet.execute();
        jSet x = (jSet) reTestIt(jSet, ff);
        assert claims.get(SUBJECT).equals(eppn);
        assert claims2.get(SUBJECT).equals(eppn);
        // now create a completely new claim and set its value
        jSet = new jSet(claims);
        jSet.addArg("blarg");
        jSet.addArg(eppn);
        jSet.execute();
        x = (jSet) reTestIt(jSet, ff);

        assert claims.get("blarg").equals(eppn);
        assert claims2.get("blarg").equals(eppn);

    }

    /**
     * Test the getting a claim works.
     *
     * @throws Exception
     */
    @Test
    public void testGet() throws Exception {

        Map<String, Object> claims = createClaims();
        OA2FunctorFactory ff = new OA2FunctorFactory(claims);
        jGet jGet = new jGet(claims);
        jGet.execute();
        // no args returns an empty string.
        assert jGet.getStringResult().equals("");
        assert reTestIt(jGet, ff).getStringResult().equals("");
        jGet.reset();
        jGet.addArg(SUBJECT);
        jGet.execute();
        assert jGet.getStringResult().equals(claims.get(SUBJECT));
        assert reTestIt(jGet, ff).getStringResult().equals(claims.get(SUBJECT));
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

    /**
     * Since setting VO person for various clients is hard, this is a test to show that the logic works and
     * to make sure it keeps working.
     *
     * @throws Exception
     */
    @Test
    public void testVoPersonTest() throws Exception {
          /*
          if defined(eppn) then return eppn;
          if defined(eptid) then return eptid;
          if (idp = "http://orcid.org/oauth/authorize") then return oidc (replacing "^http://" with "^https://");
          if (idp = "http://google.com/accounts/o8/id") then return oidc+"@"+"accounts.google.com";
          if (idp = "http://github.com/login/oauth/authorize") then return oidc+"@"+"github.com";
           */
        VOP_eppn();
        VOP_eptid();
        VOP_orcid();
        VOP_google();
        VOP_github();
    }


    protected void VOP_eppn() throws Exception {
        Map<String, Object> claims = doLSSTTest("eppn", EPPN, NCSA_IDP);
        assert claims.containsKey(VOPersonKey);
        assert claims.get(VOPersonKey).equals(EPPN);
    }

    @Test
    public void testXORLBTest() throws Exception {

    }

    protected void VOP_eptid() throws Exception {
        Map<String, Object> claims = doLSSTTest("eptid", EPTID, NCSA_IDP);
        assert claims.containsKey(VOPersonKey);
        assert claims.get(VOPersonKey).equals(EPTID);

    }

    protected void VOP_orcid() throws Exception {
        Map<String, Object> claims = doLSSTTest("oidc", orcid, ORCID_IDP);
        assert claims.containsKey(VOPersonKey);
        assert claims.get(VOPersonKey).equals(orcid.replace("http://", "https://"));
    }

    protected void VOP_github() throws Exception {
        Map<String, Object> claims = doLSSTTest("oidc", oidc, GITHUB_IDP);
        assert claims.containsKey(VOPersonKey);
        assert claims.get(VOPersonKey).equals(oidc + "@github.com");

    }

    protected void VOP_google() throws Exception {
        Map<String, Object> claims = doLSSTTest("oidc", oidc, GOOGLE_IDP);
        assert claims.containsKey(VOPersonKey);
        assert claims.get(VOPersonKey).equals(oidc + "@accounts.google.com");
    }

    public static String oidc = "oidc-" + getRandomString();// type of oidc id from google, github
    public static String orcid = "http://orcid.org/1234-5678-8765-4321"; // type from orcid
    public static String EPPN = "bob@bigstate.edu";
    public static String EPTID = "bob@random.stuff.eptid";
    public static String VOPersonKey = "voPersonExternalID";
    public static String GOOGLE_IDP = "http://google.com/accounts/o8/id";
    public static String GITHUB_IDP = "http://github.com/login/oauth/authorize";
    public static String ORCID_IDP = "http://orcid.org/oauth/authorize";
    public static String NCSA_IDP = "https://ncsa/blah/blah/woof/woof";

    /**
     * Key = claim name, value = claim value. This tests against those.
     *
     * @param key
     * @param value
     * @throws Exception
     */

    protected Map<String, Object> doLSSTTest(String key, String value, String idp) throws Exception {
        Map<String, Object> claims2 = createClaims();
        claims2.put(key, value);
        claims2.put("idp", idp);
        jXOr jXOr = createXOR(claims2);
        jXOr.execute();
       /* if (key.equals("eppn")) {
            // just print out one of them
            System.out.println("\n=================\nVO person test conditional:");
            System.out.println(jXOr.toJSON().toString(1));
        }*/
        return claims2;
    }

    protected jXOr createXOR(Map<String, Object> claims2) {
        OA2FunctorFactory ff = new OA2FunctorFactory(claims2);

        jXOr jXOr = new jXOr();
        jXOr.addArg(createLB(ff,
                "{\"$hasClaim\":[\"eppn\"]}",
                "{\"$set\":[\"" + VOPersonKey + "\",{\"$get\":[\"eppn\"]}]}"));
        jXOr.addArg(createLB(ff,
                "{\"$hasClaim\":[\"eptid\"]}",
                "{\"$set\":[\"" + VOPersonKey + "\",{\"$get\":[\"eptid\"]}]}"));
        jXOr.addArg(createLB(ff,
                "{\"$equals\":[{\"$get\":[\"idp\"]},\"" + GITHUB_IDP + "\"]}",
                "{\"$set\":[\"" + VOPersonKey + "\",{\"$concat\":[{\"$get\":[\"oidc\"]},\"@github.com\"]}]}"));
        jXOr.addArg(createLB(ff,
                "{\"$equals\":[{\"$get\":[\"idp\"]},\"" + GOOGLE_IDP + "\"]}",
                "{\"$set\":[\"" + VOPersonKey + "\",{\"$concat\":[{\"$get\":[\"oidc\"]},\"@accounts.google.com\"]}]}"));
        jXOr.addArg(createLB(ff,
                "{\"$equals\":[{\"$get\":[\"idp\"]},\"" + ORCID_IDP + "\"]}",
                "{\"$set\":[\"" + VOPersonKey + "\",{\"$replace\":[{\"$get\":[\"oidc\"]},\"http://\",\"https://\"]}]}"));

        return jXOr;
    }

    private LogicBlock createLB(OA2FunctorFactory ff, String rawIf, String rawThen) {
        jIf eppnIf = new jIf();
        JFunctor eppnExists = ff.create(rawIf);
        eppnIf.addArg(eppnExists);

        JFunctor setFromEPPN = ff.create(rawThen);
        jThen eppnThen = new jThen();
        eppnThen.addArg(setFromEPPN);
        return new LogicBlock(ff, eppnIf, eppnThen);
    }

    String rawJSON2="{\n" +
            "  \"config\": \"LSST client configuration, created by JeffGaynor 6/19/2018\",\n" +
            "  \"claims\": {\n" +
            "    \"sourceConfig\": [\n" +
            "      {\n" +
            "        \"ldap\": {\n" +
            "          \"preProcessing\": [\n" +
            "            {\n" +
            "              \"$if\": [\n" +
            "                {\n" +
            "                  \"$match\": [\n" +
            "                    \"${idp}\",\n" +
            "                    \"https://idp.ncsa.illinois.edu/idp/shibboleth\"\n" +
            "                  ]\n" +
            "                }\n" +
            "              ],\n" +
            "              \"$then\": [\n" +
            "                {\n" +
            "                  \"$set\": [\n" +
            "                    \"foo\",\n" +
            "                    {\n" +
            "                      \"$drop\": [\n" +
            "                        \"@ncsa.illinois.edu\",\n" +
            "                        \"${eppn}\"\n" +
            "                      ]\n" +
            "                    }\n" +
            "                  ]\n" +
            "                }\n" +
            "              ],\n" +
            "              \"$else\": [{\"$get_claims\": [\"$false\"]}]\n" +
            "            }\n" +
            "          ],\n" +
            "          \"postProcessing\": [\n" +
            "            {\n" +
            "              \"$if\": [\n" +
            "                {\n" +
            "                  \"$match\": [\n" +
            "                    \"${idp}\",\n" +
            "                    \"https://idp.ncsa.illinois.edu/idp/shibboleth\"\n" +
            "                  ]\n" +
            "                }\n" +
            "              ],\n" +
            "              \"$then\": [\n" +
            "                {\n" +
            "                  \"$set\": [\n" +
            "                    \"sub\",\n" +
            "                    {\"$get\": [\"eppn\"]}\n" +
            "                  ]\n" +
            "                },\n" +
            "                {\"$exclude\": [\"foo\"]}\n" +
            "              ]\n" +
            "            }\n" +
            "          ],\n" +
            "          \"failOnError\": \"false\",\n" +
            "          \"address\": \"ldap.ncsa.illinois.edu\",\n" +
            "          \"port\": 636,\n" +
            "          \"enabled\": \"true\",\n" +
            "          \"authorizationType\": \"none\",\n" +
            "          \"searchName\": \"foo\",\n" +
            "          \"searchAttributes\": [\n" +
            "            {\n" +
            "              \"name\": \"mail\",\n" +
            "              \"returnAsList\": false,\n" +
            "              \"returnName\": \"email\"\n" +
            "            },\n" +
            "            {\n" +
            "              \"name\": \"uid\",\n" +
            "              \"returnAsList\": false,\n" +
            "              \"returnName\": \"uid\"\n" +
            "            },\n" +
            "            {\n" +
            "              \"name\": \"uidNumber\",\n" +
            "              \"returnAsList\": false,\n" +
            "              \"returnName\": \"uidNumber\"\n" +
            "            },\n" +
            "            {\n" +
            "              \"name\": \"cn\",\n" +
            "              \"returnAsList\": false,\n" +
            "              \"returnName\": \"name\"\n" +
            "            },\n" +
            "            {\n" +
            "              \"name\": \"memberOf\",\n" +
            "              \"isGroup\": true,\n" +
            "              \"returnAsList\": false,\n" +
            "              \"returnName\": \"isMemberOf\"\n" +
            "            }\n" +
            "          ],\n" +
            "          \"searchBase\": \"ou=People,dc=ncsa,dc=illinois,dc=edu\",\n" +
            "          \"contextName\": \"\",\n" +
            "          \"ssl\": {\n" +
            "            \"tlsVersion\": \"TLS\",\n" +
            "            \"useJavaTrustStore\": true\n" +
            "          },\n" +
            "          \"name\": \"3258ed63b62d1a78\"\n" +
            "        }\n" +
            "      }\n" +
            "    ],\n" +
            "    \"preProcessing\": [\n" +
            "      {\n" +
            "        \"$if\": [\"$true\"],\n" +
            "        \"$then\": [\n" +
            "          {\n" +
            "            \"$set_claim_source\": [\n" +
            "              \"LDAP\",\n" +
            "              \"3258ed63b62d1a78\"\n" +
            "            ]\n" +
            "          }\n" +
            "        ]\n" +
            "      }\n" +
            "    ],\n" +
            "    \"postProcessing\": {\n" +
            "      \"$xor\": [\n" +
            "        {\n" +
            "          \"$if\": [{\"$hasClaim\": [\"eppn\"]}],\n" +
            "          \"$then\": [\n" +
            "            {\n" +
            "              \"$set\": [\n" +
            "                \"voPersonExternalID\",\n" +
            "                {\"$get\": [\"eppn\"]}\n" +
            "              ]\n" +
            "            }\n" +
            "          ]\n" +
            "        },\n" +
            "        {\n" +
            "          \"$if\": [{\"$hasClaim\": [\"eptid\"]}],\n" +
            "          \"$then\": [\n" +
            "            {\n" +
            "              \"$set\": [\n" +
            "                \"voPersonExternalID\",\n" +
            "                {\"$get\": [\"eptid\"]}\n" +
            "              ]\n" +
            "            }\n" +
            "          ]\n" +
            "        },\n" +
            "        {\n" +
            "          \"$if\": [\n" +
            "            {\n" +
            "              \"$equals\": [\n" +
            "                {\"$get\": [\"idp\"]},\n" +
            "                \"http://github.com/login/oauth/authorize\"\n" +
            "              ]\n" +
            "            }\n" +
            "          ],\n" +
            "          \"$then\": [\n" +
            "            {\n" +
            "              \"$set\": [\n" +
            "                \"voPersonExternalID\",\n" +
            "                {\n" +
            "                  \"$concat\": [\n" +
            "                    {\"$get\": [\"oidc\"]},\n" +
            "                    \"@github.com\"\n" +
            "                  ]\n" +
            "                }\n" +
            "              ]\n" +
            "            }\n" +
            "          ]\n" +
            "        },\n" +
            "        {\n" +
            "          \"$if\": [\n" +
            "            {\n" +
            "              \"$equals\": [\n" +
            "                {\"$get\": [\"idp\"]},\n" +
            "                \"http://google.com/accounts/o8/id\"\n" +
            "              ]\n" +
            "            }\n" +
            "          ],\n" +
            "          \"$then\": [\n" +
            "            {\n" +
            "              \"$set\": [\n" +
            "                \"voPersonExternalID\",\n" +
            "                {\n" +
            "                  \"$concat\": [\n" +
            "                    {\"$get\": [\"oidc\"]},\n" +
            "                    \"@accounts.google.com\"\n" +
            "                  ]\n" +
            "                }\n" +
            "              ]\n" +
            "            }\n" +
            "          ]\n" +
            "        },\n" +
            "        {\n" +
            "          \"$if\": [\n" +
            "            {\n" +
            "              \"$equals\": [\n" +
            "                {\"$get\": [\"idp\"]},\n" +
            "                \"http://orcid.org/oauth/authorize\"\n" +
            "              ]\n" +
            "            }\n" +
            "          ],\n" +
            "          \"$then\": [\n" +
            "            {\n" +
            "              \"$set\": [\n" +
            "                \"voPersonExternalID\",\n" +
            "                {\n" +
            "                  \"$replace\": [\n" +
            "                    {\"$get\": [\"oidc\"]},\n" +
            "                    \"http://\",\n" +
            "                    \"https://\"\n" +
            "                  ]\n" +
            "                }\n" +
            "              ]\n" +
            "            }\n" +
            "          ]\n" +
            "        }\n" +
            "      ]\n" +
            "    }\n" +
            "  },\n" +
            "  \"isSaved\": false\n" +
            "}\n";

    @Test
    public void testLBXOr() throws Throwable {
        String rawJSON = "{\"config\":\"LSST client configuration, created by JeffGaynor 6/19/2018\",\"claims\":{\"sourceConfig\":[{\"ldap\":{\"preProcessing\":[{\"$if\":[{\"$match\":[\"${idp}\",\"https://idp.ncsa.illinois.edu/idp/shibboleth\"]}],\"$then\":[{\"$set\":[\"foo\",{\"$drop\":[\"@ncsa.illinois.edu\",\"${eppn}\"]}]}],\"$else\":[{\"$get_claims\":[\"$false\"]}]}],\"postProcessing\":[{\"$if\":[{\"$match\":[\"${idp}\",\"https://idp.ncsa.illinois.edu/idp/shibboleth\"]}],\"$then\":[{\"$set\":[\"sub\",{\"$get\":[\"eppn\"]}]},{\"$exclude\":[\"foo\"]}]}],\"failOnError\":\"false\",\"address\":\"ldap.ncsa.illinois.edu\",\"port\":636,\"enabled\":\"true\",\"authorizationType\":\"none\",\"searchName\":\"foo\",\"searchAttributes\":[{\"name\":\"mail\",\"returnAsList\":false,\"returnName\":\"email\"},{\"name\":\"uid\",\"returnAsList\":false,\"returnName\":\"uid\"},{\"name\":\"uidNumber\",\"returnAsList\":false,\"returnName\":\"uidNumber\"},{\"name\":\"cn\",\"returnAsList\":false,\"returnName\":\"name\"},{\"name\":\"memberOf\",\"isGroup\":true,\"returnAsList\":false,\"returnName\":\"isMemberOf\"}],\"searchBase\":\"ou=People,dc=ncsa,dc=illinois,dc=edu\",\"contextName\":\"\",\"ssl\":{\"tlsVersion\":\"TLS\",\"useJavaTrustStore\":true},\"name\":\"3258ed63b62d1a78\"}}],\"preProcessing\":[{\"$if\":[\"$true\"],\"$then\":[{\"$set_claim_source\":[\"LDAP\",\"3258ed63b62d1a78\"]}]}]}," +
                "\"postProcessing\":{\"$xor\":[{\"$if\":[{\"$hasClaim\":[\"eppn\"]}],\"$then\":[{\"$set\":[\"voPersonExternalID\",{\"$get\":[\"eppn\"]}]}]},{\"$if\":[{\"$hasClaim\":[\"eptid\"]}],\"$then\":[{\"$set\":[\"voPersonExternalID\",{\"$get\":[\"eptid\"]}]}]},{\"$if\":[{\"$equals\":[{\"$get\":[\"idp\"]},\"http://github.com/login/oauth/authorize\"]}],\"$then\":[{\"$set\":[\"voPersonExternalID\",{\"$concat\":[{\"$get\":[\"oidc\"]},\"@github.com\"]}]}]},{\"$if\":[{\"$equals\":[{\"$get\":[\"idp\"]},\"http://google.com/accounts/o8/id\"]}],\"$then\":[{\"$set\":[\"voPersonExternalID\",{\"$concat\":[{\"$get\":[\"oidc\"]},\"@accounts.google.com\"]}]}]},{\"$if\":[{\"$equals\":[{\"$get\":[\"idp\"]},\"http://orcid.org/oauth/authorize\"]}],\"$then\":[{\"$set\":[\"voPersonExternalID\",{\"$replace\":[{\"$get\":[\"oidc\"]},\"http://\",\"https://\"]}]}]}]}," +
                "\"isSaved\":false}";

        JSONObject cfg = JSONObject.fromObject(rawJSON2);
        // make a fake transaction so this is testable in jUnit.
        JSONObject claims = createClaims();
        // Put something in there so the test can work.
         claims.put(IDP_CLAIM, "http://google.com/accounts/o8/id");
        String randomString  = getRandomString();
         claims.put("oidc", randomString);

        OA2FunctorFactory functorFactory = new OA2FunctorFactory(claims);
        OA2ClientConfigurationFactory ff = new OA2ClientConfigurationFactory(functorFactory);
        OA2ClientConfiguration clientConfiguration = ff.newInstance(cfg);
        ff.createClaimSource(clientConfiguration, cfg);

        JSONObject postProcessing = OA2ClientConfigurationUtil.getClaimsPostProcessing(cfg);
        //JSONObject postProcessing = cfg.getJSONObject("postProcessing");

        //LDAPClaimsSource claimsSource = new LDAPClaimsSource(ldapConfiguration, null);
        LogicBlocks postProcessor = functorFactory.createLogicBlock(postProcessing);
        assert postProcessor instanceof XORLogicBlocks;
        postProcessor.execute();
        assert (boolean) postProcessor.getResult();
        assert claims.containsKey(VOPersonKey);
        assert claims.getString(VOPersonKey).equals(randomString + "@accounts.google.com");
    }
}

