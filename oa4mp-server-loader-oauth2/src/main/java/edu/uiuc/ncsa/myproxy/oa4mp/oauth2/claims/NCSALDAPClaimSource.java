package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims;
import edu.uiuc.ncsa.security.oauth_2_0.server.config.LDAPConfiguration;
import edu.uiuc.ncsa.security.oauth_2_0.server.config.LDAPConfigurationUtil;
import net.sf.json.JSONObject;

/**
 * An {@link LDAPClaimsSource} for the NCSA. This has the more common  defaults.
 * <p>Created by Jeff Gaynor<br>
 * on 10/5/18 at  12:32 PM
 */
public class NCSALDAPClaimSource extends LDAPClaimsSource {
    public NCSALDAPClaimSource() {
    }

    public NCSALDAPClaimSource(String searchNameKey) {
        super();
        init();
        if (searchNameKey != null && !searchNameKey.isEmpty()) {
            getLDAPCfg().setSearchNameKey(searchNameKey);
        } else {
            getLDAPCfg().setSearchNameKey(OA2Claims.SUBJECT);
        }

    }

    public NCSALDAPClaimSource(LDAPConfiguration ldapConfiguration, MyLoggingFacade myLogger) {
        super(ldapConfiguration, myLogger);
    }

    public NCSALDAPClaimSource(OA2SE oa2SE) {
        super(oa2SE);
    }

    String rawConfig = " {\n" +
            "        \"ldap\": {\n" +
            "          \"id\": \"ncsa-default\",\n" +
            "          \"name\": \"ncsa-default\",\n" +
            "          \"address\": \"ldap.ncsa.illinois.edu\",\n" +
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
            "            \"password\": \"changeit\",\n" +
            "            \"type\": \"jks\"\n" +
            "          }\n" +
            "        }\n" +
            "      }";

    protected void init() {
        LDAPConfigurationUtil util = new LDAPConfigurationUtil();
        JSONObject cfg = JSONObject.fromObject(rawConfig);
        LDAPConfiguration x = util.fromJSON(cfg);
        setConfiguration(x);
    }
}
