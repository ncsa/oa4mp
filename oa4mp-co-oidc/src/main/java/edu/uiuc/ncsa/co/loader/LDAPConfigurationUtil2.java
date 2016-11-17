package edu.uiuc.ncsa.co.loader;

import edu.uiuc.ncsa.security.delegation.storage.JSONUtil;
import edu.uiuc.ncsa.security.oauth_2_0.server.LDAPConfiguration;
import edu.uiuc.ncsa.security.oauth_2_0.server.LDAPConfigurationUtil;
import edu.uiuc.ncsa.security.util.ssl.SSLConfiguration;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

/**
 * Adds JSON support.
 * <p/>
 * A utility that loads the configuration from a node and has the tags, etc. for it.
 * <p>Created by Jeff Gaynor<br>
 * on 5/4/16 at  8:50 AM
 */
public class LDAPConfigurationUtil2 extends LDAPConfigurationUtil {
    public static JSONObject toJSON(LDAPConfiguration configuration) {
        JSONUtil jsonUtil = getJSONUtil();
        JSONObject ldap = new JSONObject();
        JSONObject content = new JSONObject();
        ldap.put(LDAP_TAG, content);

        jsonUtil.setJSONValue(ldap, LDAP_ADDRESS_TAG, configuration.getServer());
        jsonUtil.setJSONValue(ldap, LDAP_PORT_TAG, configuration.getPort());
        jsonUtil.setJSONValue(ldap, LDAP_ENABLED_TAG, configuration.isEnabled());
        jsonUtil.setJSONValue(ldap, LDAP_AUTH_TYPE, configuration.getAuthType());
        if (configuration.getAuthType() == LDAP_AUTH_NONE_KEY) {
            jsonUtil.setJSONValue(ldap, LDAP_AUTH_TYPE, LDAP_AUTH_NONE);

            // nothing to do
        }
        if (configuration.getAuthType() == LDAP_AUTH_SIMPLE_KEY) {
            jsonUtil.setJSONValue(ldap, LDAP_AUTH_TYPE, LDAP_AUTH_SIMPLE);

            jsonUtil.setJSONValue(ldap, LDAP_PASSWORD_TAG, configuration.getPassword());
            jsonUtil.setJSONValue(ldap, LDAP_SECURITY_PRINCIPAL_TAG, configuration.getSecurityPrincipal());
        }

        // Now for the search attributes
        JSONArray searchAttributes = new JSONArray();
        for (String key : configuration.getSearchAttributes().keySet()) {
            AttributeEntry ae = configuration.getSearchAttributes().get(key);
            JSONObject entry = new JSONObject();
            entry.put("name", ae.sourceName);
            entry.put(RETURN_AS_LIST, ae.isList);
            entry.put(RETURN_NAME, ae.targetName);
            searchAttributes.add(entry);
        }
        jsonUtil.setJSONValue(ldap, LDAP_SEARCH_ATTRIBUTES_TAG, searchAttributes);
        jsonUtil.setJSONValue(ldap, LDAP_SEARCH_BASE_TAG, configuration.getSearchBase());
        jsonUtil.setJSONValue(ldap, LDAP_CONTEXT_NAME_TAG, configuration.getContextName());
        if (configuration.getSslConfiguration() != null) {
            JSONObject jsonSSL = SSLConfigurationUtil2.toJSON(configuration.getSslConfiguration());
            jsonUtil.setJSONValue(ldap, SSLConfigurationUtil2.SSL_TAG, jsonSSL.getJSONObject(SSLConfigurationUtil2.SSL_TAG));
        }
        return ldap;
    }

    static JSONUtil jsonUtil = null;

    protected static JSONUtil getJSONUtil() {
        if (jsonUtil == null) {
            jsonUtil = new JSONUtil(LDAP_TAG);
        }
        return jsonUtil;
    }


    public static LDAPConfiguration fromJSON(JSONObject json) {
        JSONUtil jsonUtil = getJSONUtil();

        LDAPConfiguration config = new LDAPConfiguration();
        config.setContextName(jsonUtil.getJSONValueString(json, LDAP_CONTEXT_NAME_TAG));
        config.setEnabled(jsonUtil.getJSONValueBoolean(json, LDAP_ENABLED_TAG));
        String x = jsonUtil.getJSONValueString(json, LDAP_AUTH_TYPE);
        config.setAuthType(getAuthType(x)); // default
        config.setServer(jsonUtil.getJSONValueString(json, LDAP_ADDRESS_TAG));
        config.setPort(jsonUtil.getJSONValueInt(json, LDAP_PORT_TAG));
        Object se = jsonUtil.getJSONValue(json, LDAP_SEARCH_ATTRIBUTES_TAG);
        if (se instanceof JSONArray) {
            JSONArray searchAttributes = (JSONArray) se;
            //LinkedList<AttributeEntry> attributeEntries = new LinkedList<>();
            for (int i = 0; i < searchAttributes.size(); i++) {
                JSONObject current = searchAttributes.getJSONObject(i);
                String name = current.getString("name");
                String targetName = current.getString(RETURN_NAME);
                boolean isList = current.getBoolean(RETURN_AS_LIST);
                AttributeEntry attributeEntry = new AttributeEntry(name, targetName, isList);
                config.getSearchAttributes().put(attributeEntry.sourceName, attributeEntry);
            }

            config.setSearchBase(jsonUtil.getJSONValueString(json, LDAP_SEARCH_BASE_TAG));
            config.setSecurityPrincipal(jsonUtil.getJSONValueString(json, LDAP_SECURITY_PRINCIPAL_TAG));
            config.setPassword(jsonUtil.getJSONValueString(json, LDAP_PASSWORD_TAG));
            JSONObject jsonSSL = new JSONObject();
            jsonSSL.put(SSLConfigurationUtil2.SSL_TAG, jsonUtil.getJSONValue(json, SSLConfigurationUtil2.SSL_TAG));
            SSLConfiguration sslConfiguration = SSLConfigurationUtil2.fromJSON(jsonSSL);
            config.setSslConfiguration(sslConfiguration);
        }
        return config;
    }
}
