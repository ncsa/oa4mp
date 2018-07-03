package test;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.FunctorClaimsType;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.OA2FunctorFactory;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.jExclude;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.jSet;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.flows.jSetClaimSource;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.HTTPHeaderClaimsSource;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.LDAPClaimsSource;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.state.OA2ClientConfiguration;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.state.OA2ClientConfigurationFactory;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.ClaimSource;
import edu.uiuc.ncsa.security.oauth_2_0.server.config.LDAPConfiguration;
import edu.uiuc.ncsa.security.oauth_2_0.server.config.LDAPConfigurationUtil;
import edu.uiuc.ncsa.security.util.TestBase;
import edu.uiuc.ncsa.security.util.functor.FunctorTypeImpl;
import edu.uiuc.ncsa.security.util.functor.LogicBlock;
import edu.uiuc.ncsa.security.util.functor.logic.jContains;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.junit.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static edu.uiuc.ncsa.myproxy.oa4mp.oauth2.state.OA2ClientConfigurationUtil.*;
import static edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims.AUDIENCE;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/18/18 at  11:19 AM
 */
public class ClientConfigurationTest extends TestBase {
    /*
    Create a configuration object. This lets you set a custom claim as well as the original audience
    claim and a new value that will be reset (via a jSet functor) during processing.
     */
    protected JSONObject createConfiguration(String customClaim,
                                             String oldAudience,
                                             String newAudience) throws Throwable {
        JSONObject cfg = new JSONObject();
        // claims is a container for all claim configuration relating to sources and processing.
        // Note that the JSON library we use clones objects when adding them, so if you create a JSONObject
        // and put it in another, then populate it, nothing will be in the enclosing object.
        // Therefore, you must populate everything completely and assemble it all only as the final step.
        JSONObject claims = new JSONObject();
        cfg.put(CONFIG_KEY, "Comment");
        // Add some sources
        JSONArray claimSources = setupSources();

        // Add some claim processing logic
        JSONObject claimProcessing = setupProcessing(oldAudience, newAudience);

        // Add in the configurations for claims
        JSONArray claimConfigs = new JSONArray();

        // Add configuration for a source. Here an LDAP.
        LDAPConfiguration ldap =getLDAP();
        JSONObject ldap2 = LDAPConfigurationUtil.toJSON(ldap);
        ldap = LDAPConfigurationUtil.fromJSON(ldap2);
        ldap.setName("LDAP2");
        System.out.println(LDAPConfigurationUtil.toJSON(ldap));
        claimConfigs.add(LDAPConfigurationUtil.toJSON(ldap));
        JSONObject logic = setupRuntime(customClaim);

        // add the parts to the configuration
        setClaimSources(cfg, claimSources);
        setClaimsPostProcessing(cfg, claimProcessing);
        setClaimSourcesConfigurations(cfg, claimConfigs);
        setRuntime(cfg, logic);
        return cfg;
    }

    protected static String MY_CLAIM = "myClaim"; // key for custom claim in testing
    protected static String MY_CLAIM2 = "myClaim2"; // key for custom claim in testing

    /*
    sets up a bunch of randome source and two good ones, LDAP2 and HTTP
     */
    private JSONArray setupSources() {
        JSONArray claimSources = new JSONArray();
        JSONObject src1 = new JSONObject();
        src1.put(CLAIM_SOURCE_ALIAS_KEY, "LDAP2");
        src1.put(CLAIM_SOURCE_CLASSNAME_KEY, LDAPClaimsSource.class.getCanonicalName());
        claimSources.add(src1);

        src1 = new JSONObject();
        src1.put(CLAIM_SOURCE_ALIAS_KEY, "HTTP");
        src1.put(CLAIM_SOURCE_CLASSNAME_KEY, HTTPHeaderClaimsSource.class.getCanonicalName());
        claimSources.add(src1);
        // now add some cruft
        for (int i = 0; i < 5; i++) {
            src1 = new JSONObject();
            src1.put(CLAIM_SOURCE_ALIAS_KEY, getRandomString());
            src1.put(CLAIM_SOURCE_CLASSNAME_KEY, getRandomString());
            claimSources.add(src1);
        }
        return claimSources;
    }


    protected Map<String, Object> createClaims() {
        return OA2FunctorTests.createClaims();
    }

    protected JSONObject setupProcessing(String oldAud, String newAud) {
        JSONArray array = new JSONArray();
        Map<String, Object> claims = createClaims();
        claims.put(AUDIENCE, oldAud);
        JSONObject ifBlock = new JSONObject();

        jContains jContains = new jContains();
        jContains.addArg("foo");
        jContains.addArg("zfoo");
        ifBlock.put("$if", jContains.toJSON());
        jSet set = new jSet(claims); // we won't process this, just use it's toJSON to get valid JSON
        set.addArg(AUDIENCE);
        set.addArg(newAud);

        jExclude jExclude = new jExclude(claims);
        jExclude.addArg(MY_CLAIM2);
        JSONArray thenArray = new JSONArray();
        thenArray.add(set.toJSON());
        thenArray.add(jExclude.toJSON());
        ifBlock.put("$then", thenArray);
        array.add(ifBlock);

        JSONObject j = new JSONObject();
        j.put(FunctorTypeImpl.OR.getValue(), array);
        return j;
    }

    /*
    This creates n if block for the runtime. It will set a claim source and it will set a custom claim.
    In this way claims may be created before processing. This facility effectively allows for setting and
     using variables.
     */
    protected JSONObject setupRuntime(String myClaim) {
        JSONArray array = new JSONArray();
        JSONObject ifBlock = new JSONObject();

        jContains jContains = new jContains();
        jContains.addArg("foo");
        jContains.addArg("zfoo");
        ifBlock.put("$if", jContains.toJSON());

        jSetClaimSource jSetClaimSource = new jSetClaimSource();
        jSetClaimSource.addArg("LDAP2");
        jSetClaimSource.addArg("LDAP2");
        // This tests that a claim can be set for further use. I.e. that claims may be created.
        jSet set = new jSet(new HashMap<String, Object>()); // we won't process this, just use it's toJSON to get valid JSON
        set.addArg(MY_CLAIM);
        set.addArg(myClaim);
        JSONArray thenArray = new JSONArray();
        thenArray.add(set.toJSON());
        thenArray.add(jSetClaimSource.toJSON());
        set = new jSet(null);
        set.addArg(MY_CLAIM2);
        set.addArg(myClaim);
        ifBlock.put("$then", thenArray);
        array.add(ifBlock);
        JSONObject j = new JSONObject();
        j.put(FunctorTypeImpl.OR.getValue(), array);
        return j;
    }

    protected LDAPConfiguration getLDAP(){
        String raw="{\"ldap\": {\n" +
                "  \"address\": \"ldap.ncsa.illinois.edu\",\n" +
                "  \"port\": 636,\n" +
                "  \"enabled\": true,\n" +
                "  \"authorizationType\": \"none\",\n" +
                "  \"failOnError\": false,\n" +
                "  \"notifyOnFail\": false,\n" +
                "  \"searchAttributes\":   [\n" +
                "        {\n" +
                "      \"name\": \"mail\",\n" +
                "      \"returnAsList\": false,\n" +
                "      \"returnName\": \"mail\"\n" +
                "    },\n" +
                "        {\n" +
                "      \"name\": \"cn\",\n" +
                "      \"returnAsList\": false,\n" +
                "      \"returnName\": \"name\"\n" +
                "    },\n" +
                "        {\n" +
                "      \"name\": \"memberOf\",\n" +
                "      \"returnAsList\": false,\n" +
                "      \"returnName\": \"isMemberOf\"\n" +
                "    }\n" +
                "  ],\n" +
                "  \"searchBase\": \"ou=People,dc=ncsa,dc=illinois,dc=edu\",\n" +
                "  \"searchName\": \"eppn\",\n" +
                "  \"contextName\": \"\",\n" +
                "  \"ssl\":   {\n" +
                "    \"keystore\": {},\n" +
                "    \"tlsVersion\": \"TLS\",\n" +
                "    \"useJavaTrustStore\": true,\n" +
                "    \"password\": \"changeit\",\n" +
                "    \"type\": \"jks\"\n" +
                "  }\n" +
                "}}";
        return LDAPConfigurationUtil.fromJSON(JSONObject.fromObject(raw));
    }
    /**
     * This sets up the claims from the configuration and verifies they exist as they should.
     *
     * @throws Throwable
     */

    @Test
    public void testSetupClaimSources() throws Throwable {
        String r = Long.toHexString(System.currentTimeMillis());
        String myClaim = "my-claim-" + r;
        String oldAud = "old-aud-" + r;
        String newAud = "new-aud-" + r;
        System.out.println("my claim=" + myClaim);
        System.out.println("old aud=" + oldAud);
        System.out.println("new aud=" + newAud);
        JSONObject cfg = createConfiguration(myClaim, oldAud, newAud);

        OA2ClientConfigurationFactory<OA2ClientConfiguration> ff = new OA2ClientConfigurationFactory(new OA2FunctorFactory(null));
        OA2ClientConfiguration clientConfiguration = ff.newInstance(cfg);
        assert clientConfiguration.executeRuntime();
        ff.createClaimSource(clientConfiguration, cfg);
        List<ClaimSource> cc = clientConfiguration.getClaimSource();
        System.out.println(cc);
        assert cc.get(0) instanceof LDAPClaimsSource;

    }
    // TODO -- Need a test for setting up a processor,
    // * enabling/disabling based on claims
    // * post-processing of claims
    // * moving claims processing out of AT servlet.
    // * stashing of state into transaction, including things like ACR claim if it exists.

    @Test
    public void testProcessor() throws Throwable {
        String r = Long.toHexString(System.currentTimeMillis());
        String myClaim = "my-claim-" + r;
        String oldAud = "old-aud-" + r;
        String newAud = "new-aud-" + r;
        System.out.println("my claim=" + myClaim);
        System.out.println("old aud=" + oldAud);
        System.out.println("new aud=" + newAud);

        JSONObject cfg = createConfiguration(myClaim, oldAud, newAud);
        System.out.println(cfg.toString(2));

        OA2ClientConfigurationFactory<OA2ClientConfiguration> ff = new OA2ClientConfigurationFactory(new OA2FunctorFactory(null));
        OA2ClientConfiguration clientConfiguration = ff.newInstance(cfg);
        clientConfiguration.executeRuntime();
        ff.createClaimSource(clientConfiguration, cfg);

        // claims do not exist until the sources have been run (??)
        Map<String, Object> claims = createClaims();

        ff = new OA2ClientConfigurationFactory(new OA2FunctorFactory(claims));
        clientConfiguration = ff.newInstance(cfg);
        clientConfiguration.executeRuntime();
        ff.setupPostProcessing(clientConfiguration, cfg);

        clientConfiguration.executePostProcessing();
        assert claims.get(AUDIENCE).toString().equals(newAud) : "Expected audience =\"" + newAud + "\" but got \"" + claims.get(AUDIENCE) + "\"";

        assert claims.containsKey(MY_CLAIM);
        assert claims.get(MY_CLAIM).equals(myClaim);
        // check that the next claim was removed.
        assert !claims.containsKey(MY_CLAIM2);
        // test puts in an exlcuded claim. This is not used until much later, when the claims are written.
        // This just verifies that the system got the list and is handling it right up to this point.
        for(LogicBlock lb: clientConfiguration.getPostProcessing()){
            assert lb.getThenBlock().getFunctorMap().containsKey(FunctorClaimsType.EXCLUDE.getValue());
        }

    }

    @Test
       public void testInclude() throws Throwable {
           String r = Long.toHexString(System.currentTimeMillis());
           String myClaim = "my-claim-" + r;
           String oldAud = "old-aud-" + r;
           String newAud = "new-aud-" + r;
           System.out.println("my claim=" + myClaim);
           System.out.println("old aud=" + oldAud);
           System.out.println("new aud=" + newAud);

           JSONObject cfg = createConfiguration(myClaim, oldAud, newAud);
           System.out.println(cfg.toString(2));

           OA2ClientConfigurationFactory<OA2ClientConfiguration> ff = new OA2ClientConfigurationFactory(new OA2FunctorFactory(null));
           OA2ClientConfiguration clientConfiguration = ff.newInstance(cfg);
           clientConfiguration.executeRuntime();
           ff.createClaimSource(clientConfiguration, cfg);

           // claims do not exist until the sources have been run (??)
           Map<String, Object> claims = createClaims();

           ff = new OA2ClientConfigurationFactory(new OA2FunctorFactory(claims));
           clientConfiguration = ff.newInstance(cfg);
           clientConfiguration.executeRuntime();
           ff.setupPostProcessing(clientConfiguration, cfg);

           clientConfiguration.executePostProcessing();
           assert claims.get(AUDIENCE).toString().equals(newAud) : "Expected audience =\"" + newAud + "\" but got \"" + claims.get(AUDIENCE) + "\"";

           assert claims.containsKey(MY_CLAIM);
           assert claims.get(MY_CLAIM).equals(myClaim);
           // check that the next claim was removed.
           assert !claims.containsKey(MY_CLAIM2);
           // test puts in an exlcuded claim. This is not used until much later, when the claims are written.
           // This just verifies that the system got the list and is handling it right up to this point.
           for(LogicBlock lb: clientConfiguration.getPostProcessing()){
               assert lb.getThenBlock().getFunctorMap().containsKey(FunctorClaimsType.EXCLUDE.getValue());
           }

       }
}
