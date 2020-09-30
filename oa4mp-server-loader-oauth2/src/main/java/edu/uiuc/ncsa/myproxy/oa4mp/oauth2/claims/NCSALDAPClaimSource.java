package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims;
import edu.uiuc.ncsa.security.oauth_2_0.server.config.LDAPConfiguration;
import edu.uiuc.ncsa.security.oauth_2_0.server.config.LDAPConfigurationUtil;
import edu.uiuc.ncsa.security.servlet.ServletDebugUtil;
import net.sf.json.JSONObject;

/**
 * An {@link LDAPClaimsSource} for the NCSA. This has the more common  defaults.
 * <p>Created by Jeff Gaynor<br>
 * on 10/5/18 at  12:32 PM
 */
public class NCSALDAPClaimSource extends LDAPClaimsSource {
    public static final String DEFAULT_SEACH_NAME = "uid";

    /**
     * No arg constructor is needed for invocation by reflection. 
     */
    public NCSALDAPClaimSource() {
    }

    /**
     * NOTE that his uses the search filter attribute == the name of the claim to look up and
     * search on (like sub, uid) and if it is missing will default to using the
     * sub claim.
     * @param claimName
     */

    public NCSALDAPClaimSource(String claimName) {
        super();
        ServletDebugUtil.trace(this, "In constructor.");
        init();
        if (claimName != null && !claimName.isEmpty()) {
            getLDAPCfg().setSearchFilterAttribute(claimName);
        } else {
            getLDAPCfg().setSearchFilterAttribute(OA2Claims.SUBJECT);
        }
       ServletDebugUtil.trace(this, "Set the search filter attribute =\"" + getLDAPCfg().getSearchFilterAttribute() + "\".");
    }

    public NCSALDAPClaimSource(LDAPConfiguration ldapConfiguration, MyLoggingFacade myLogger) {
        super(ldapConfiguration, myLogger);
    }



    public NCSALDAPClaimSource(OA2SE oa2SE) {
        super(oa2SE);
    }
    // This is to test that this works.
    String rawConfig = " {\n" +
            "        \"ldap\": {\n" +
            "          \"id\": \"ncsa-default\",\n" +
            "          \"name\": \"ncsa-default\",\n" +
            "          \"address\": \"ldap4.ncsa.illinois.edu, ldap2.ncsa.illinois.edu,ldap1.ncsa.illinois.edu\",\n" +
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
            "              \"isGroup\": true,\n" +
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

    protected void init() {
        LDAPConfigurationUtil util = new LDAPConfigurationUtil();
        JSONObject cfg = JSONObject.fromObject(rawConfig);
        LDAPConfiguration x = util.fromJSON(cfg);
        ServletDebugUtil.trace(this, "In init(). Setting configuration");
        setConfiguration(x);
    }
}
