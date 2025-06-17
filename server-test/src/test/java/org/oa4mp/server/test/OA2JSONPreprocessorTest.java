package org.oa4mp.server.test;

import org.oa4mp.delegation.server.server.config.LDAPConfiguration;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.util.JSONPreprocessorTest;
import edu.uiuc.ncsa.security.util.json.JSONEntry;
import edu.uiuc.ncsa.security.util.json.JSONStore;
import edu.uiuc.ncsa.security.util.json.PreProcessor;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.junit.Test;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/28/19 at  5:41 PM
 */
public class OA2JSONPreprocessorTest extends JSONPreprocessorTest {
    public Identifier ID_PRE_PROCESSOR = BasicIdentifier.newID("id:pre");
    public String ID_POST_PROCESSOR = "id:post";

    public String preproc =
            "{\"preProcessing\": {\n" +
                    "            \"script\": [\n" +
                    "              \"# Set some variables to keep the verbosity down. These are mostly the IDPs.\",\n" +
                    "              \"# Note that this must run only before the first LDAP query.\",\n" +
                    "              \"setEnv('vi','voPersonExternalID');\",\n" +
                    "              \"setEnv('github','http://github.com/login/oauth/authorize');\",\n" +
                    "              \"setEnv('google','http://google.com/accounts/o8/id');\",\n" +
                    "              \"setEnv('orcid','http://orcid.org/oauth/authorize');\",\n" +
                    "              \"setEnv('ncsa','https://idp.ncsa.illinois.edu/idp/shibboleth');\",\n" +
                    "              \"#  Now figure out which IDP was used and set voPersonExternalID so it may be searched for.\",\n" +
                    "              \"xor{\",\n" +
                    "              \"    if[equals(get('idp'),'${github}')]then[set('${vi}',concat(get('oidc'),'@github.com'))],\",\n" +
                    "              \"    if[equals(get('idp'),'${google}')]then[set('${vi}',concat(get('oidc'),'@accounts.google.com'))],\",\n" +
                    "              \"    if[equals(get('idp'),'${orcid}')]then[set('${vi}',replace(get('oidc'),'http://','https://'))],\",\n" +
                    "              \"    if[hasClaim('eppn')]then[set('${vi}',get('eppn'))],\",\n" +
                    "              \"    if[hasClaim('eptid')]then[set('${vi}',get('eptid'))]\",\n" +
                    "              \"};\"\n" +
                    "            ],\n" +
                    "            \"version\": \"1.0\"\n" +
                    "          }\n" +
                    "       }";

    @Override
    protected void populateStore(JSONStore store) {
        super.populateStore(store);
        JSONObject prep = JSONObject.fromObject(preproc);
        JSONEntry jsonEntry = new JSONEntry(ID_PRE_PROCESSOR);
        jsonEntry.setRawContent(prep.toString());
        jsonEntry.setType(JSONEntry.TYPE_JSON_OBJECT);
        store.put(ID_PRE_PROCESSOR, jsonEntry);

    }

    /**
     * This creates a script from fragments and then runs it.
     * @throws Exception
     */
    @Test public void testCreateScript() throws Exception{
        JSONArray caput = new JSONArray();

        String[] head =
                {"setEnv('vi','voPersonExternalID');\n" ,
                "setEnv('github','http://github.com/login/oauth/authorize');\n" ,
                "setEnv('google','http://google.com/accounts/o8/id');\n" ,
                "setEnv('orcid','http://orcid.org/oauth/authorize');\n" ,
                "# Here is a comment"};
        for(String x : head){
            caput.add(x);
        }


        JSONArray cauda = new JSONArray();
        String[] tail = {"if[\n",
                "    endsWith(getEnv('orcid'),'ize')\n",
                "   ]then[\n",
                "     echo('got one')\n",
                "   ]else[\n",
                "     echo('newp')\n",
                "];"};
        for(String y: tail){
            cauda.add(y);
        }

    }
    @Test
    public void testOtherLDAP() throws Exception {
        LDAPConfiguration cfg = new LDAPConfiguration();
        cfg.setPort(636);
        cfg.setServer("https://foo.bar");
        JSONObject json = cfg.toJSON();
        System.out.println(json.toString(2));
    }

    String rawLDAP = "{\"ldap\": {" +
            "  \"address\": \"ldap.ncsa.illinois.edu\",\n" +
            "  \"port\": 636,\n" +
            "  \"" + PreProcessor.IMPORT_DIRECTIVE + "\":\"" + ID_PRE_PROCESSOR.toString() + "\"\n" +
            "}" +
            "}";

    /**
     * This tests that replacements in a JSON configuration file can be done at the correct level in LDAP.
     *
     * @throws Exception
     */
    @Test
    public void testLDAP() throws Exception {
        PreProcessor pp = createPP();
        System.out.println(rawLDAP);
        JSONObject ldap = JSONObject.fromObject(rawLDAP);
        JSONObject post = (JSONObject) pp.execute(ldap);

        System.out.println(post.toString(2));
    }


}
