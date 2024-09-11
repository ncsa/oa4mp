package org.oa4mp.server.loader.qdl.claims;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.oa4mp.server.loader.oauth2.claims.*;
import org.oa4mp.server.loader.oauth2.storage.transactions.OA2ServiceTransaction;
import org.oa4mp.server.loader.qdl.scripting.OA2State;
import org.qdl_lang.evaluate.IOEvaluator;
import org.qdl_lang.expressions.ConstantNode;
import org.qdl_lang.expressions.Polyad;
import org.qdl_lang.extensions.QDLFunction;
import org.qdl_lang.state.State;
import org.qdl_lang.variables.Constant;
import org.qdl_lang.variables.QDLList;
import org.qdl_lang.variables.QDLStem;

import java.util.ArrayList;
import java.util.List;

import static org.qdl_lang.variables.QDLStem.STEM_INDEX_MARKER;

/**
 * QDLFunction to convert claims to a stem. For use in the OA4MP QDL module.
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

    ConfigtoCS configtoCS = null;

    protected ConfigtoCS getConfigToCS() {
        if (configtoCS == null) {
            configtoCS = new ConfigtoCS();
        }
        return configtoCS;
    }

    @Override
    public Object evaluate(Object[] objects, State state) {
        if (objects.length < 2) {
            throw new IllegalArgumentException(getName() + " requires at least two arguments");
        }
        if (!(objects[0] instanceof QDLStem)) {
            throw new IllegalArgumentException(getName() + " requires a stem variable as its first argument");
        }

        QDLStem arg = (QDLStem) objects[0];
        if (objects[1] == null || !(objects[1] instanceof String)) {
            throw new IllegalArgumentException(getName() + " requires the name of the user as its second argument");
        }
        String username = (String) objects[1];
        if (!arg.containsKey(CS_DEFAULT_TYPE)) {
            throw new IllegalStateException(getName() + " must have the type of claim source");
        }
        QDLStem headers = null;
        if (arg.getString(CS_DEFAULT_TYPE).equals(CS_TYPE_FILTER_HEADERS)) {
            headers = (QDLStem) arg.get("headers.");
        }
        switch (arg.getString(CS_DEFAULT_TYPE)) {
            case CS_TYPE_CODE:
                return doCode(arg, username, headers, state);
            case CS_TYPE_FILE:
                return doFS(arg, username, state);
            case CS_TYPE_LDAP:
                return doLDAP(arg, username, state);
            case CS_TYPE_FILTER_HEADERS:
                return doHeaders(arg, username, headers, state);
            case CS_TYPE_ALL_HEADERS:
                return doQDLHeaders(arg, username, headers, state);
            case CS_TYPE_NCSA:
                return doNCSA(arg, username, state);
        }
        return null;
    }

    /**
     * Process the QDL utility for headers.
     * @param arg
     * @param username
     * @param headers
     * @param state
     * @return
     */
    private QDLStem doQDLHeaders(QDLStem arg, String username, QDLStem headers, State state) {
        OA2State oa2State = null;
         if (state instanceof OA2State) {
             oa2State = (OA2State) state;
         }
         QDLHeadersClaimsSource qdlHeaderClaimsSource = (QDLHeadersClaimsSource) getConfigToCS().convert(arg, oa2State == null ? null : oa2State.getOa2se());
         if(state instanceof OA2State) {
             qdlHeaderClaimsSource.setOa2State((OA2State) state);
         }
         OA2ServiceTransaction t = new OA2ServiceTransaction((Identifier) null);
         t.setUsername(username);
         JSONObject protoClaims = t.getUserMetaData();

         TestHTTPRequest req = new TestHTTPRequest(headers);
         JSONObject j = qdlHeaderClaimsSource.process(protoClaims, req, t);
         QDLStem output = new QDLStem();
         output.fromJSON(j);
         return output;
    }

    protected QDLStem doCode(QDLStem arg, String username, QDLStem headers, State state) {
        OA2State oa2State = null;
        if (state instanceof OA2State) {
            oa2State = (OA2State) state;
        }
        BasicClaimsSourceImpl basicClaimsSource = (BasicClaimsSourceImpl) getConfigToCS().convert(arg, oa2State == null ? null : oa2State.getOa2se());
        OA2ServiceTransaction t = new OA2ServiceTransaction((Identifier) null);
        t.setUsername(username);
        JSONObject claims = new JSONObject();
        TestHTTPRequest req = new TestHTTPRequest(headers);
        claims = basicClaimsSource.process(claims, req, t);
        QDLStem output = new QDLStem();
        output.fromJSON(claims);
        return output;

    }

    protected QDLStem doNCSA(QDLStem arg, String username, State state) {
        OA2State oa2State = null;
        if (state instanceof OA2State) {
            oa2State = (OA2State) state;
        }
        DebugUtil.setIsEnabled(true);
        DebugUtil.setDebugLevel(DebugUtil.DEBUG_LEVEL_TRACE);
        NCSALDAPClaimSource ncsaldapClaimSource = (NCSALDAPClaimSource) getConfigToCS().convert(arg, (oa2State == null ? null : oa2State.getOa2se()));
        OA2ServiceTransaction t = new OA2ServiceTransaction((Identifier) null);
        t.setUsername(username);
        JSONObject protoClaims = new JSONObject();
        protoClaims.put(NCSALDAPClaimSource.DEFAULT_SEACH_NAME, username);

        JSONObject j = ncsaldapClaimSource.process(protoClaims, t);
        QDLStem output = new QDLStem();
        output.fromJSON(j);
        return output;
    }

    public QDLStem doHeaders(QDLStem arg, String username, QDLStem headers, State state) {
        OA2State oa2State = null;
        if (state instanceof OA2State) {
            oa2State = (OA2State) state;
        }
        HTTPHeaderClaimsSource httpHeaderClaimsSource = (HTTPHeaderClaimsSource) getConfigToCS().convert(arg, oa2State == null ? null : oa2State.getOa2se());

        OA2ServiceTransaction t = new OA2ServiceTransaction((Identifier) null);
        t.setUsername(username);
        JSONObject protoClaims = new JSONObject();

        TestHTTPRequest req = new TestHTTPRequest(headers);
        JSONObject j = httpHeaderClaimsSource.process(protoClaims, req, t);
        QDLStem output = new QDLStem();
        output.fromJSON(j);
        return output;

    }

    /**
     * This does the get and makes a dummy transaction with the right name. This means a claim name
     * of uid should always be used.
     *
     * @param arg
     * @param username
     * @param state
     * @return
     */
    private QDLStem doLDAP(QDLStem arg, String username, State state) {
        OA2State oa2State = null;
        if (state instanceof OA2State) {
            oa2State = (OA2State) state;
        }
        LDAPClaimsSource ldapClaimsSource = (LDAPClaimsSource) getConfigToCS().convert(arg, oa2State == null ? null : oa2State.getOa2se());
        OA2ServiceTransaction t = new OA2ServiceTransaction((Identifier) null);
        t.setUsername(username);
        JSONObject protoClaims = new JSONObject();
        protoClaims.put(arg.getString(CS_LDAP_SEARCH_NAME), username);
        JSONObject j = ldapClaimsSource.process(protoClaims, t);
        QDLStem output = claimsToStem(j);
        // CIL-1426 -- we do not want to return the parameter we created,
        // HOWEVER there is nothing at all stopping them from searching for this parameter and getting it back
        // THEREFORE, only return it if it changed.
        // This way, if there are no hits, the user gets an empty claim list, showing nothing was found,
        // rather than a false positive that there was a single attribute (actually the one we passed in)
        // in the claim source.
        if (output.containsKey(arg.getString(CS_LDAP_SEARCH_NAME)) && output.getString(arg.getString(CS_LDAP_SEARCH_NAME)).equals(username)) {
            output.remove(arg.getString(CS_LDAP_SEARCH_NAME));
        }
        return output;
    }

    /**
     * It is a bit hard to convert from stems to claims, so this does it.
     *
     * @param claims
     * @return
     */
    protected QDLStem claimsToStem(JSONObject claims) {
        QDLStem out = new QDLStem();
        for (Object k : claims.keySet()) {
            String key = k.toString();
            Object obj = claims.get(k);
            if (obj instanceof JSONObject) {
                out.put(k + STEM_INDEX_MARKER, claimsToStem((JSONObject) obj));
            } else {
                if (obj instanceof JSONArray) {
                    JSONArray array = (JSONArray) obj;
                    // turn in to stemList
                    QDLList sl = new QDLList();
                    for (int i = 0; i < array.size(); i++) {
                        Object obj1 = array.get(i);
                        QDLStem out1 = null;
                        if (obj1 instanceof JSONObject) {
                            out1 = claimsToStem((JSONObject) obj1);
                            sl.append(out1);
                        } else {
                            sl.append(array.get(i));
                        }
                    }
                    QDLStem st1 = new QDLStem();
                    st1.setQDLList(sl);
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
     *
     * @param arg
     * @param username
     * @param state
     * @return
     */
    protected QDLStem doFS(QDLStem arg, String username, State state) {
        OA2State oa2State = null;
        if (state instanceof OA2State) {
            oa2State = (OA2State) state;
        }
        String rawJSON = null;
        // resolve files against VFS's so scripts have access to them in server mode.
        if (arg.containsKey(CS_FILE_STEM_CLAIMS)) {
            Object ooo = arg.get(CS_FILE_STEM_CLAIMS);
            if (!(ooo instanceof QDLStem)) {
                throw new IllegalArgumentException("the " + CS_FILE_STEM_CLAIMS + " argument must be a stem of claims");
            }
            rawJSON = ((QDLStem) ooo).toJSON().toString();
        }else{
            if (arg.containsKey(CS_FILE_FILE_PATH)) {
                Polyad polyad = new Polyad(IOEvaluator.READ_FILE);
                polyad.addArgument(new ConstantNode(arg.getString(CS_FILE_FILE_PATH), Constant.STRING_TYPE));
                state.getMetaEvaluator().evaluate(polyad, state);
                rawJSON = polyad.getResult().toString();
            }
        }
        if (rawJSON == null) {
            throw new IllegalStateException("neither a path to the claims nor a stem of claims has been given");
        }
        FSClaimSource fsClaimSource = (FSClaimSource) getConfigToCS().convert(arg, oa2State, oa2State == null ? null : oa2State.getOa2se());
        fsClaimSource.setRawJSON(rawJSON);
        OA2ServiceTransaction t = new OA2ServiceTransaction((Identifier) null);
        t.setUsername(username);
        JSONObject claims = fsClaimSource.process(new JSONObject(), t);
        QDLStem output = new QDLStem();
        output.fromJSON(claims);
        return output;

    }


    protected static void testFS() {
        QDLStem mystem = new QDLStem();
        mystem.put(CS_DEFAULT_TYPE, CS_TYPE_FILE);
        mystem.put(CS_FILE_FILE_PATH, DebugUtil.getDevPath() + "/oa4mp/server-test/src/main/resources/test-claims.json");
        CreateSourceConfig csc = new CreateSourceConfig();
        QDLStem out = (QDLStem) csc.evaluate(new Object[]{mystem}, null);
        System.out.println(out.toJSON().toString(2));


        ClaimsSourceGetter cst = new ClaimsSourceGetter();
        QDLStem claims = (QDLStem) cst.evaluate(new Object[]{mystem, "jeff"}, null);
        System.out.println("File claim source configuration:");
        System.out.println(claims.toJSON().toString(2));
    }

    protected static void testLDAP2() {
        QDLStem mystem = new QDLStem();

        mystem.put(CS_DEFAULT_TYPE, CS_TYPE_LDAP);
        mystem.put(CS_LDAP_SERVER_ADDRESS, "ldap1.ncsa.illinois.edu,ldap2.ncsa.illinois.edu");
        mystem.put(CS_LDAP_SEARCH_FILTER_ATTRIBUTE, "uid");
        mystem.put(CS_LDAP_SEARCH_BASE, "ou=People,dc=ncsa,dc=illinois,dc=edu");
        mystem.put(CS_LDAP_SEARCH_NAME, "uid");
        mystem.put(CS_LDAP_AUTHZ_TYPE, "none");
        CreateSourceConfig createSourceConfig = new CreateSourceConfig();
        QDLStem cfg = (QDLStem) createSourceConfig.evaluate(new Object[]{mystem}, null);

        ClaimsSourceGetter cst = new ClaimsSourceGetter();
        QDLStem claims = (QDLStem) cst.evaluate(new Object[]{cfg, "jgaynor"}, null);
        System.out.println(claims.toJSON().toString(2));

    }

    protected static void testNCSA() {
        CreateSourceConfig csc = new CreateSourceConfig();
        QDLStem cfg = new QDLStem();

        csc.doNCSA(new QDLStem(), cfg); // populates the cfg
        System.out.println("NCSA default config:" + cfg.toString(1));
        ClaimsSourceGetter cst = new ClaimsSourceGetter();
        QDLStem claims = (QDLStem) cst.evaluate(new Object[]{cfg, "jgaynor"}, null);
        System.out.println(claims.toString(2));

    }

    protected static void testLDAP() {
        QDLStem mystem = new QDLStem();
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
        QDLStem sa = new QDLStem();
        sa.addList(searchAttr);
        QDLStem groupNames = new QDLStem();

        groupNames.put("0", "memberOf");
        mystem.put(CS_LDAP_SEARCH_ATTRIBUTES, sa);
        mystem.put(CS_LDAP_GROUP_NAMES, groupNames);
        System.out.println("\n-----\nldap cfg:\n-----\n" + mystem.toString(1));
        ClaimsSourceGetter cst = new ClaimsSourceGetter();
        QDLStem claims = (QDLStem) cst.evaluate(new Object[]{mystem, "jgaynor"}, null);
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
