package edu.uiuc.ncsa.myproxy.oa4mp.qdl.claims;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.*;
import edu.uiuc.ncsa.myproxy.oa4mp.qdl.scripting.OA2State;
import edu.uiuc.ncsa.qdl.evaluate.IOEvaluator;
import edu.uiuc.ncsa.qdl.expressions.ConstantNode;
import edu.uiuc.ncsa.qdl.expressions.Polyad;
import edu.uiuc.ncsa.qdl.extensions.QDLFunction;
import edu.uiuc.ncsa.qdl.state.State;
import edu.uiuc.ncsa.qdl.variables.Constant;
import edu.uiuc.ncsa.qdl.variables.StemEntry;
import edu.uiuc.ncsa.qdl.variables.StemList;
import edu.uiuc.ncsa.qdl.variables.StemVariable;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

import static edu.uiuc.ncsa.qdl.variables.StemVariable.STEM_INDEX_MARKER;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/10/20 at  10:18 AM
 */
public class ClaimsSourceGetter implements QDLFunction, CSConstants {
    public static final String GET_CLAIMS_NAME = "get_claims";

    @Override
    public String getName() {
        return GET_CLAIMS_NAME;
    }

    @Override
    public int[] getArgCount() {
        return new int[]{2};
    }

    @Override
    public Object evaluate(Object[] objects, State state) {
        if (objects.length < 2) {
            throw new IllegalArgumentException("Error: " + getName() + " requires at least two arguments");
        }
        if (!(objects[0] instanceof StemVariable)) {
            throw new IllegalArgumentException("Error: " + getName() + " requires a stem variable as its first argument");
        }

        StemVariable arg = (StemVariable) objects[0];
        if (objects[1] == null || !(objects[1] instanceof String)) {
            throw new IllegalArgumentException("Error: " + getName() + " requires the name of the user as its second argument");
        }
        String username = (String) objects[1];
        if (!arg.containsKey(CS_DEFAULT_TYPE)) {
            throw new IllegalStateException("Error: " + getName() + " must have the type of claim source");
        }
        StemVariable headers = null;
        if (arg.getString(CS_DEFAULT_TYPE).equals(CS_TYPE_HEADERS)) {
            headers = (StemVariable) arg.get("headers.");
        }
        switch (arg.getString(CS_DEFAULT_TYPE)) {
            case CS_TYPE_CODE:
                return doCode(arg, username, headers, state);
            case CS_TYPE_FILE:
                return doFS(arg, username, state);
            case CS_TYPE_LDAP:
                return doLDAP(arg, username, state);
            case CS_TYPE_HEADERS:
                return doHeaders(arg, username, headers, state);
            case CS_TYPE_NCSA:
                return doNCSA(arg, username, state);
        }
        return null;
    }

    protected StemVariable doCode(StemVariable arg, String username, StemVariable headers, State state) {
        OA2State oa2State = null;
        if(state instanceof OA2State) {
            oa2State = (OA2State) state;
        }
        BasicClaimsSourceImpl basicClaimsSource = (BasicClaimsSourceImpl) ConfigtoCS.convert(arg, oa2State==null?null:oa2State.getOa2se());
        OA2ServiceTransaction t = new OA2ServiceTransaction((Identifier) null);
        t.setUsername(username);
        JSONObject claims = new JSONObject();
        TestHTTPRequest req = new TestHTTPRequest(headers);
        claims = basicClaimsSource.process(claims, req, t);
        StemVariable output = new StemVariable();
        output.fromJSON(claims);
        return output;

    }

    protected StemVariable doNCSA(StemVariable arg, String username, State state) {
        OA2State oa2State = null;
        if(state instanceof OA2State) {
             oa2State = (OA2State) state;
        }
        DebugUtil.setIsEnabled(true);
        DebugUtil.setDebugLevel(DebugUtil.DEBUG_LEVEL_TRACE);
        NCSALDAPClaimSource ncsaldapClaimSource = (NCSALDAPClaimSource) ConfigtoCS.convert(arg, (oa2State==null?null:oa2State.getOa2se()));
        OA2ServiceTransaction t = new OA2ServiceTransaction((Identifier) null);
        t.setUsername(username);
        JSONObject protoClaims = new JSONObject();
        protoClaims.put(NCSALDAPClaimSource.DEFAULT_SEACH_NAME, username);

        JSONObject j = ncsaldapClaimSource.process(protoClaims, t);
        StemVariable output = new StemVariable();
        output.fromJSON(j);
        return output;
    }

    public StemVariable doHeaders(StemVariable arg, String username, StemVariable headers, State state) {
        OA2State oa2State = null;
        if(state instanceof OA2State){
            oa2State = (OA2State) state;
        }
        HTTPHeaderClaimsSource httpHeaderClaimsSource = (HTTPHeaderClaimsSource) ConfigtoCS.convert(arg, oa2State==null?null:oa2State.getOa2se());

        OA2ServiceTransaction t = new OA2ServiceTransaction((Identifier) null);
        t.setUsername(username);
        JSONObject protoClaims = new JSONObject();

        TestHTTPRequest req = new TestHTTPRequest(headers);
        JSONObject j = httpHeaderClaimsSource.process(protoClaims, req, t);
        StemVariable output = new StemVariable();
        output.fromJSON(j);
        return output;

    }


    private StemVariable doLDAP(StemVariable arg, String username, State state) {
        OA2State oa2State = null;
        if(state instanceof OA2State){
            oa2State = (OA2State) state;
        }
        LDAPClaimsSource ldapClaimsSource = (LDAPClaimsSource) ConfigtoCS.convert(arg, oa2State==null?null:oa2State.getOa2se());
        OA2ServiceTransaction t = new OA2ServiceTransaction((Identifier) null);
        t.setUsername(username);
        JSONObject protoClaims = new JSONObject();
        protoClaims.put(arg.getString(CS_LDAP_SEARCH_NAME), username);
        JSONObject j = ldapClaimsSource.process(protoClaims, t);
        StemVariable output = claimsToStem(j);
        return output;
    }

    /**
     * It is a bit hard to convert from stems to claims, so this does it.
     *
     * @param claims
     * @return
     */
    protected StemVariable claimsToStem(JSONObject claims) {
        StemVariable out = new StemVariable();
        for (Object k : claims.keySet()) {
            String key = k.toString();
            Object obj = claims.get(k);
            if (obj instanceof JSONObject) {
                out.put(k + STEM_INDEX_MARKER, claimsToStem((JSONObject) obj));
            } else {
                if (obj instanceof JSONArray) {
                    JSONArray array = (JSONArray) obj;
                    // turn in to stemList
                    StemList<StemEntry> sl = new StemList<>();
                    for (int i = 0; i < array.size(); i++) {
                        Object obj1 = array.get(i);
                        StemVariable out1 = null;
                        if (obj1 instanceof JSONObject) {
                            out1 = claimsToStem((JSONObject) obj1);
                            sl.append(out1);
                        } else {
                            sl.append(array.get(i));
                        }
                    }
                    StemVariable st1 = new StemVariable();
                    st1.setStemList(sl);
                    out.put(key + STEM_INDEX_MARKER, st1);
                } else {
                    out.put(key, obj.toString());
                }
            }
        }
        return out;
    }

    /*
vfs_cfg.type :='pass_through';
vfs_cfg.scheme := 'vfs2';
vfs_cfg.mount_point := '/test2';
vfs_cfg.access := 'rw';
vfs_cfg.root_dir := '/home/ncsa/dev/ncsa-git/oa4mp/oa4mp-server-admin-oauth2/src/main/resources/qdl/weitzel';
vfs_mount(vfs_cfg.);
cfg. := new_template('file')
cfg.file_path := 'vfs2#/test2/test-claims.json'
get_claims(cfg., 'dweitzel2@unl.edu')
     */

    /**
     * Note that this needs to send a transaction to the {@link FSClaimSource},
     * so it creates one and sets the user name. Practically then the
     * {@link #CS_FILE_CLAIM_KEY} then is ignored, since the function accepts
     * the username directly.
     * @param arg
     * @param username
     * @param state
     * @return
     */
    protected StemVariable doFS(StemVariable arg, String username, State state) {
        OA2State oa2State = null;
        if(state instanceof OA2State){
            oa2State = (OA2State) state;
        }
        // resolve files against VFS's so scripts have access to them in server mode.
        Polyad polyad = new Polyad(IOEvaluator.READ_FILE);
        polyad.addArgument(new ConstantNode(arg.getString(CS_FILE_FILE_PATH), Constant.STRING_TYPE));
        state.getMetaEvaluator().evaluate(polyad, state);
        String rawJSON = polyad.getResult().toString();
        FSClaimSource fsClaimSource = (FSClaimSource) ConfigtoCS.convert(arg, oa2State == null?null:oa2State.getOa2se());
        fsClaimSource.setRawJSON(rawJSON);
        OA2ServiceTransaction t = new OA2ServiceTransaction((Identifier) null);
        t.setUsername(username);
        JSONObject claims = fsClaimSource.process(new JSONObject(), t);
        StemVariable output = new StemVariable();
        output.fromJSON(claims);
        return output;

    }


    protected static void testFS() {
        StemVariable mystem = new StemVariable();
        mystem.put(CS_DEFAULT_TYPE, CS_TYPE_FILE);
        mystem.put(CS_FILE_FILE_PATH, "/home/ncsa/dev/ncsa-git/oa4mp/oa4mp-server-test-oauth2/src/main/resources/test-claims.json");
        CreateSourceConfig csc = new CreateSourceConfig();
        StemVariable out = (StemVariable) csc.evaluate(new Object[]{mystem}, null);
        System.out.println(out.toJSON().toString(2));


        ClaimsSourceGetter cst = new ClaimsSourceGetter();
        StemVariable claims = (StemVariable) cst.evaluate(new Object[]{mystem, "jeff"}, null);
        System.out.println("File claim source configuration:");
        System.out.println(claims.toJSON().toString(2));
    }

    protected static void testLDAP2() {
        StemVariable mystem = new StemVariable();

        mystem.put(CS_DEFAULT_TYPE, CS_TYPE_LDAP);
        mystem.put(CS_LDAP_SERVER_ADDRESS, "ldap1.ncsa.illinois.edu,ldap2.ncsa.illinois.edu");
        mystem.put(CS_LDAP_SEARCH_FILTER_ATTRIBUTE, "uid");
        mystem.put(CS_LDAP_SEARCH_BASE, "ou=People,dc=ncsa,dc=illinois,dc=edu");
        mystem.put(CS_LDAP_SEARCH_NAME, "uid");
        mystem.put(CS_LDAP_AUTHZ_TYPE, "none");
        CreateSourceConfig createSourceConfig = new CreateSourceConfig();
        StemVariable cfg = (StemVariable) createSourceConfig.evaluate(new Object[]{mystem}, null);

        ClaimsSourceGetter cst = new ClaimsSourceGetter();
        StemVariable claims = (StemVariable) cst.evaluate(new Object[]{cfg, "jgaynor"}, null);
        System.out.println(claims.toJSON().toString(2));

    }

    protected static void testNCSA() {
        CreateSourceConfig csc = new CreateSourceConfig();
        StemVariable cfg = new StemVariable();

        csc.doNCSA(new StemVariable(), cfg); // populates the cfg
        System.out.println("NCSA default config:" + cfg.toString(1));
        ClaimsSourceGetter cst = new ClaimsSourceGetter();
        StemVariable claims = (StemVariable) cst.evaluate(new Object[]{cfg, "jgaynor"}, null);
        System.out.println(claims.toString(2));

    }

    protected static void testLDAP() {
        StemVariable mystem = new StemVariable();
        mystem.put(CS_DEFAULT_TYPE, CS_TYPE_LDAP);
        mystem.put(CS_LDAP_SERVER_ADDRESS, "ldap4.ncsa.illinois.edu,ldap2.ncsa.illinois.edu,ldap1.ncsa.illinois.edu");
        mystem.put(CS_LDAP_AUTHZ_TYPE, "none");
        mystem.put(CS_LDAP_SEARCH_NAME, "uid");
        mystem.put(CS_DEFAULT_IS_ENABLED, Boolean.TRUE);
        mystem.put(CS_LDAP_SEARCH_FILTER_ATTRIBUTE, "uid");
        mystem.put(CS_LDAP_SEARCH_BASE, "ou=People,dc=ncsa,dc=illinois,dc=edu");

        ArrayList<Object> searchAttr = new ArrayList<>();
        searchAttr.add("mail");
        searchAttr.add("uid");
        searchAttr.add("uidNumber");
        searchAttr.add("cn");
        searchAttr.add("memberOf");
        StemVariable sa = new StemVariable();
        sa.addList(searchAttr);
        StemVariable groupNames = new StemVariable();

        groupNames.put("0", "memberOf");
        mystem.put(CS_LDAP_SEARCH_ATTRIBUTES, sa);
        mystem.put(CS_LDAP_GROUP_NAMES, groupNames);
        System.out.println("\n-----\nldap cfg:\n-----\n" + mystem.toString(1));
        ClaimsSourceGetter cst = new ClaimsSourceGetter();
        StemVariable claims = (StemVariable) cst.evaluate(new Object[]{mystem, "jgaynor"}, null);
        System.out.println(claims.toString(2));

    }

    public static void main(String[] args) {
        System.out.println("Testing File System claims");
        testFS();
        System.out.println("Testing LDAP claims");
        testLDAP();
        System.out.println("Testing NCSA claims");
        testNCSA();

    }

    @Override
    public List<String> getDocumentation(int argCount) {
        ArrayList<String> docs = new ArrayList<>();
        docs.add(getName() + "(config., user_name) -- test a given claims configuration, returning a stem of claims");
        docs.add("Note that this is dependent on several factors, e.g. if you are testing LDAP, you may need to be on a VPN");
        return docs;
    }

    // Next is a functional configuration, old style, so we have a reference for debugging.
    static String rawConfig = " {\n" +
            "        \"ldap\": {\n" +
            "          \"id\": \"ncsa-default\",\n" +
            "          \"name\": \"ncsa-default\",\n" +
            "          \"address\": \"ldap1.ncsa.illinois.edu,ldap2.ncsa.illinois.edu\",\n" +
            "          \"port\": 636,\n" +
            "          \"enabled\": true,\n" +
            "          \"authorizationType\": \"none\",\n" +
            "          \"failOnError\": false,\n" +
            "          \"notifyOnFail\": false,\n" +
            "          \"searchAttributes\": [\n" +
            "            {\n" +
            "              \"name\": \"mail\",\n" +
            "              \"returnAsList\": false,\n" +
            "              \"returnName\": \"email\"\n" +
            "            },\n" +
            "            {\n" +
            "              \"name\": \"cn\",\n" +
            "              \"returnAsList\": false,\n" +
            "              \"returnName\": \"name\"\n" +
            "            },\n" +
            "            {\n" +
            "              \"name\": \"uidNumber\",\n" +
            "              \"returnAsList\": false,\n" +
            "              \"returnName\": \"uidNumber\"\n" +
            "            },\n" +
            "            {\n" +
            "              \"name\": \"uid\",\n" +
            "              \"returnAsList\": false,\n" +
            "              \"returnName\": \"uid\"\n" +
            "            },\n" +
            "            {\n" +
            "              \"name\": \"memberOf\",\n" +
            "              \"IsInGroup\": true,\n" +
            "              \"returnAsList\": false,\n" +
            "              \"returnName\": \"isMemberOf\"\n" +
            "            }\n" +
            "          ],\n" +
            "          \"searchBase\": \"ou=People,dc=ncsa,dc=illinois,dc=edu\",\n" +
            "          \"searchName\": \"uid\",\n" +
            "          \"searchFilterAttribute\": \"uid\",\n" +
            "          \"contextName\": \"\",\n" +
            "          \"ssl\": {\n" +
            "            \"keystore\": {},\n" +
            "            \"tlsVersion\": \"TLS\",\n" +
            "            \"useJavaTrustStore\": true,\n" +
            //"            \"password\": \"changeit\",\n" +
            //"            \"type\": \"jks\"\n" +
            "          }\n" +
            "        }\n" +
            "      }";
}
