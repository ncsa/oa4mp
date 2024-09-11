package org.oa4mp.delegation.server.server.config;

import edu.uiuc.ncsa.security.core.configuration.Configurations;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import org.oa4mp.delegation.common.storage.JSONUtil;
import org.oa4mp.delegation.server.server.claims.ClaimSourceConfiguration;
import org.oa4mp.delegation.server.server.claims.ClaimSourceConfigurationUtil;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.util.ssl.SSLConfiguration;
import edu.uiuc.ncsa.security.util.ssl.SSLConfigurationUtil;
import net.sf.json.JSON;
import net.sf.json.JSONArray;
import net.sf.json.JSONNull;
import net.sf.json.JSONObject;
import org.apache.commons.configuration.tree.ConfigurationNode;

import java.io.Serializable;
import java.util.Collection;
import java.util.LinkedList;

import static edu.uiuc.ncsa.security.core.configuration.Configurations.*;
import static org.oa4mp.delegation.server.server.scripts.functor.ClientFunctorScriptsUtil.CLAIM_POST_PROCESSING_KEY;
import static org.oa4mp.delegation.server.server.scripts.functor.ClientFunctorScriptsUtil.CLAIM_PRE_PROCESSING_KEY;

/**
 * A utility that loads the configuration from a node and has the tags, etc. for it.
 * <p>Created by Jeff Gaynor<br>
 * on 5/4/16 at  8:50 AM
 */
public class LDAPConfigurationUtil extends ClaimSourceConfigurationUtil {
    public static final String LDAP_TAG = "ldap";
    public static final String LDAP_PASSWORD_TAG = "password";
    public static final String LDAP_ADDRESS_TAG = "address";
    public static final String LDAP_SEARCH_BASE_TAG = "searchBase";
    public static final String SEARCH_NAME_USERNAME = "username";
    public static final String SEARCH_NAME_KEY = "searchName"; // This is the name of the claim whose value is used
    public static final String SEARCH_FILTER_ATTRIBUTE_KEY = "searchFilterAttribute"; // This is the name of the attribute in LDAP to search for
    // The search is done by searchFilterAttribute=searchName, e.g. uid=eppn. The defaut filter attribute is uid.
    public static final String SEARCH_FILTER_ATTRIBUTE_DEFAULT = "uid"; // This is the default attribute name for the search
    // CIL-1553/
    public static final String SEARCH_SCOPE = "searchScope";
    public static final String SEARCH_SCOPE_SUBTREE = "subtree";
    public static final String SEARCH_SCOPE_OBJECT = "object";
    public static final String SEARCH_SCOPE_ONE_LEVEL = "one_level";

    public static final String LDAP_SEARCH_ATTRIBUTES_TAG = "searchAttributes";
    public static final String LDAP_SEARCH_ATTRIBUTE_TAG = "attribute";
    public static final String LDAP_SECURITY_PRINCIPAL_TAG = "principal";
    public static final String LDAP_PORT_TAG = "port";
    public static final String LDAP_CONTEXT_NAME_TAG = "contextName";

    public static final int DEFAULT_PORT = 636;
    public static final String LDAP_AUTH_TYPE = "authorizationType";
    public static final String LDAP_AUTH_NONE = "none";
    public static final int LDAP_AUTH_UNSPECIFIED_KEY = 0;
    public static final int LDAP_AUTH_NONE_KEY = 1;
    public static final String LDAP_AUTH_SIMPLE = "simple";
    public static final int LDAP_AUTH_SIMPLE_KEY = 10;
    public static final String LDAP_AUTH_STRONG = "strong";
    public static final int LDAP_AUTH_STRONG_KEY = 100;
    public static final String RETURN_NAME = "returnName"; // attribute for the attribute tag.E.g. <attribute returnName="foo">bar</attributte>
    public static final String RETURN_AS_LIST = "returnAsList"; // attribute for the attribute tag.E.g. <attribute returnAsList="true">bar</attributte>
    public static final String IS_GROUP = "isGroup"; // attribute telling that this is the group information.

    @Override
    public ClaimSourceConfiguration createConfiguration() {
        return new LDAPConfiguration();
    }

    @Override
    public String getComponentName() {
        return LDAP_TAG;
    }

    public static class AttributeEntry implements Serializable {
        public AttributeEntry(String sourceName, String targetName, boolean isList, boolean isGroup) {
            this.isList = isList;
            this.sourceName = sourceName;
            this.targetName = targetName;
            this.isGroup = isGroup;
        }

        public String sourceName;
        public String targetName;
        public boolean isList = false;
        public boolean isGroup = false;

        @Override
        public String toString() {
            return "AttributeEntry[" +
                    "isList=" + isList +
                    "isGroup=" + isGroup +
                    ", sourceName='" + sourceName + '\'' +
                    ", targetName='" + targetName + '\'' +
                    "]";
        }
    }

    /**
     * Converts an XML configuration into an configuration. This is used at bootstrap time if there
     * is a default configuration for the server.
     *
     * @param logger
     * @param node
     * @return
     */
    public LDAPConfiguration getLdapConfiguration(MyLoggingFacade logger, ConfigurationNode node) {
        ConfigurationNode ldapNode = Configurations.getFirstNode(node, LDAP_TAG);
        // This comes from the server configuration so we have to look for the right node to kick this off.
        LDAPConfiguration ldapConfiguration = (LDAPConfiguration) getConfiguration(logger, ldapNode);
        logger.info("Starting to load LDAP configuration.");

        if (!ldapConfiguration.isEnabled()) {
            return ldapConfiguration; // nothing to do.
        }
        // There is a configuration, so implicitly enable this.
        SSLConfiguration sslConfiguration = SSLConfigurationUtil.getSSLConfiguration(logger, ldapNode);
        ldapConfiguration.setSslConfiguration(sslConfiguration);
        String tempServer = getNodeValue(ldapNode, LDAP_ADDRESS_TAG);

        ldapConfiguration.setServer(getNodeValue(ldapNode, LDAP_ADDRESS_TAG));
        String x = getNodeValue(ldapNode, LDAP_CONTEXT_NAME_TAG);

        ldapConfiguration.setContextName(x == null ? "" : x); // set to empty string if missing.
        String searchNameKey = getNodeValue(ldapNode, SEARCH_NAME_KEY);
        if (searchNameKey != null) {
            ldapConfiguration.setSearchNameKey(searchNameKey);
        } else {
            ldapConfiguration.setSearchNameKey(SEARCH_NAME_USERNAME); //default
        }
        ldapConfiguration.setSecurityPrincipal(getNodeValue(ldapNode, LDAP_SECURITY_PRINCIPAL_TAG));
        // Do stuff related to searching
        ConfigurationNode attributeNode = getFirstNode(ldapNode, LDAP_SEARCH_ATTRIBUTES_TAG);
        if (attributeNode == null) {
            ldapConfiguration.setSearchAttributes(null);
        } else {
            for (int i = 0; i < attributeNode.getChildrenCount(); i++) {
                // only get the elements tagged as attributes in case others get added in the future.
                if (LDAP_SEARCH_ATTRIBUTE_TAG.equals(attributeNode.getChild(i).getName())) {
                    Object kid = attributeNode.getChild(i).getValue();
                    if (kid != null) {
                        String returnName = getFirstAttribute(attributeNode.getChild(i), RETURN_NAME);
                        if (returnName == null) {
                            returnName = kid.toString(); // name returned is the same as the search attribute
                        }
                        x = getFirstAttribute(attributeNode.getChild(i), RETURN_AS_LIST);
                        boolean returnAsList = false;
                        if (x != null) {
                            try {
                                returnAsList = Boolean.parseBoolean(x);
                            } catch (Throwable t) {
                                // Rock on.
                            }
                        }
                        x = getFirstAttribute(attributeNode.getChild(i), IS_GROUP);
                        boolean isGroup = false;
                        if (x != null) {
                            try {
                                isGroup = Boolean.parseBoolean(x);
                            } catch (Throwable t) {
                                // accept default
                            }
                        }
                        AttributeEntry attributeEntry = new AttributeEntry(kid.toString(), returnName, returnAsList, isGroup);
                        ldapConfiguration.getSearchAttributes().put(attributeEntry.sourceName, attributeEntry);
                    }
                }
            }
        }
        ldapConfiguration.setSearchBase(getNodeValue(ldapNode, LDAP_SEARCH_BASE_TAG));
        //   ldapConfiguration.setPort(DEFAULT_PORT);

        String port = getNodeValue(ldapNode, LDAP_PORT_TAG);

        try {
            if (port != null) {
                ldapConfiguration.setPort(Integer.parseInt(port));
            }
        } catch (Throwable t) {
            logger.warn("Could not parse port \"" + port + "\" for the LDAP handler. Using default of no port.");
        }
        String searchScope = getNodeValue(ldapNode, SEARCH_SCOPE);
        if(!StringUtils.isTrivial(searchScope)){
            ldapConfiguration.setSearchScope(searchScope);
        }
        ldapConfiguration.setPassword(getNodeValue(ldapNode, LDAP_PASSWORD_TAG));

        x = getFirstAttribute(ldapNode, LDAP_AUTH_TYPE);
        ldapConfiguration.setAuthType(getAuthType(x));

        logger.info("LDAP configuration loaded.");

        return ldapConfiguration;
    }

    public String getAuthName(int authType) {
        switch (authType) {
            case LDAP_AUTH_NONE_KEY:
                return LDAP_AUTH_NONE;
            case LDAP_AUTH_SIMPLE_KEY:
                return LDAP_AUTH_SIMPLE;
            case LDAP_AUTH_STRONG_KEY:
                return LDAP_AUTH_STRONG;
        }
        return "";
    }

    public int getAuthType(String x) {
        int rc = LDAP_AUTH_UNSPECIFIED_KEY; // default
        if (x != null) {
            // If specified, figure out what they want.
            if (x.equals(LDAP_AUTH_NONE)) {
                rc = LDAP_AUTH_NONE_KEY;
            }
            if (x.equals(LDAP_AUTH_SIMPLE)) {
                rc = LDAP_AUTH_SIMPLE_KEY;
            }
            if (x.equals(LDAP_AUTH_STRONG)) {
                rc = LDAP_AUTH_STRONG_KEY;
            }
        }
        return rc;

    }

    /**
     * Converts a collection of configuration to a {@link JSONArray} of objects.
     *
     * @param configurations
     * @return
     */
    public JSONArray toJSON(Collection<LDAPConfiguration> configurations) {
        JSONArray ldaps = new JSONArray();
        for (LDAPConfiguration ldap : configurations) {
            ldaps.add(toJSON(ldap));
        }
        return ldaps;
    }

    /**
     * Convert a single configuration to a {@link JSONObject}.
     *
     * @param configuration
     * @return
     */
    public JSONObject toJSON(LDAPConfiguration configuration) {
        JSONObject ldap = super.toJSON(configuration);
        getJSONUtil().setJSONValue(ldap, LDAP_ADDRESS_TAG, configuration.getServer());
        getJSONUtil().setJSONValue(ldap, LDAP_PORT_TAG, configuration.getPort());
        getJSONUtil().setJSONValue(ldap, LDAP_AUTH_TYPE, configuration.getAuthType());
        getJSONUtil().setJSONValue(ldap, CLAIM_PRE_PROCESSING_KEY, configuration.getJSONPreProcessing());
        getJSONUtil().setJSONValue(ldap, CLAIM_POST_PROCESSING_KEY, configuration.getJSONPostProcessing());

        if (configuration.getAuthType() == LDAP_AUTH_NONE_KEY) {
            getJSONUtil().setJSONValue(ldap, LDAP_AUTH_TYPE, LDAP_AUTH_NONE);
        }
        if (configuration.getAuthType() == LDAP_AUTH_SIMPLE_KEY) {
            getJSONUtil().setJSONValue(ldap, LDAP_AUTH_TYPE, LDAP_AUTH_SIMPLE);
            getJSONUtil().setJSONValue(ldap, LDAP_PASSWORD_TAG, configuration.getPassword());
            getJSONUtil().setJSONValue(ldap, LDAP_SECURITY_PRINCIPAL_TAG, configuration.getSecurityPrincipal());
        }
        if(configuration.hasSearchScope()){
            getJSONUtil().setJSONValue(ldap, SEARCH_SCOPE, configuration.getSearchScope());
        }
        // Now for the search attributes
        JSONArray searchAttributes = new JSONArray();
        for (String key : configuration.getSearchAttributes().keySet()) {
            AttributeEntry ae = configuration.getSearchAttributes().get(key);
            JSONObject entry = new JSONObject();
            entry.put("name", ae.sourceName);
            entry.put(RETURN_AS_LIST, ae.isList);
            entry.put(RETURN_NAME, ae.targetName);
            if (ae.isGroup) {
                // only serialize this really if it is true. Implicitly this is false.
                entry.put(IS_GROUP, ae.isGroup);
            }
            searchAttributes.add(entry);
        }
        getJSONUtil().setJSONValue(ldap, LDAP_SEARCH_ATTRIBUTES_TAG, searchAttributes);
        getJSONUtil().setJSONValue(ldap, LDAP_SEARCH_BASE_TAG, configuration.getSearchBase());
        if (configuration.getSearchNameKey() != null) {
            getJSONUtil().setJSONValue(ldap, SEARCH_NAME_KEY, configuration.getSearchNameKey());
        }
        if (configuration.getSearchFilterAttribute() != null) {
            getJSONUtil().setJSONValue(ldap, SEARCH_FILTER_ATTRIBUTE_KEY, configuration.getSearchFilterAttribute());
        }
        if (configuration.getContextName() == null) {
            getJSONUtil().setJSONValue(ldap, LDAP_CONTEXT_NAME_TAG, "");

        } else {
            getJSONUtil().setJSONValue(ldap, LDAP_CONTEXT_NAME_TAG, configuration.getContextName());
        }
        if (configuration.getSslConfiguration() != null) {
            JSONObject jsonSSL = SSLConfigurationUtil2.toJSON(configuration.getSslConfiguration());
            getJSONUtil().setJSONValue(ldap, SSLConfigurationUtil2.SSL_TAG, jsonSSL.getJSONObject(SSLConfigurationUtil2.SSL_TAG));
        }
        return ldap;
    }


    /**
     * Takes a generic {@link JSON} object and disambiguates it, returning a collection of LDAP
     * configurations.
     *
     * @param json
     * @return
     */
    public Collection<LDAPConfiguration> fromJSON(JSON json) {
        if (json instanceof JSONArray) {
            return fromJSON((JSONArray) json);
        }
        LinkedList<LDAPConfiguration> ldaps = new LinkedList<>();

        if (json instanceof JSONNull) {
            // in this case, there is no content and JSONNull is a place holder.
            return ldaps;
        }
        ldaps.add(fromJSON((JSONObject) json));
        return ldaps;
    }

    public Collection<LDAPConfiguration> fromJSON(JSONArray json) {
        LinkedList<LDAPConfiguration> ldaps = new LinkedList<>();
        for (int i = 0; i < json.size(); i++) {
            ldaps.add(fromJSON(json.getJSONObject(i)));
        }
        return ldaps;
    }

    /**
     * Check if a configuration is for ldap.
     *
     * @param json
     * @return
     */
    public boolean isLDAPCOnfig(JSONObject json) {
        return isInstanceOf(json);
    }

    /**
     * Populate an <b>existing</b> LDAPConfiguration from the JSON.
     *
     * @param claimSourceConfiguration
     * @param json
     * @return
     */
    @Override
    public LDAPConfiguration fromJSON(ClaimSourceConfiguration claimSourceConfiguration, JSONObject json) {
        super.fromJSON(claimSourceConfiguration, json);
        LDAPConfiguration config = (LDAPConfiguration) claimSourceConfiguration;

        JSONUtil jsonUtil = getJSONUtil();
        String contextName = jsonUtil.getJSONValueString(json, LDAP_CONTEXT_NAME_TAG);
        if (contextName == null) {
            config.setContextName("");
        } else {
            config.setContextName(contextName);
        }

        if(json.containsKey(SEARCH_SCOPE)){
            config.setSearchScope(json.getString(SEARCH_SCOPE));
        }
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
                boolean isGroup = false;
                if (current.containsKey(IS_GROUP)) {
                    isGroup = current.getBoolean(IS_GROUP);
                }
                AttributeEntry attributeEntry = new AttributeEntry(name, targetName, isList, isGroup);
                config.getSearchAttributes().put(attributeEntry.sourceName, attributeEntry);
            }

            config.setSearchBase(jsonUtil.getJSONValueString(json, LDAP_SEARCH_BASE_TAG));
            config.setSearchNameKey(jsonUtil.getJSONValueString(json, SEARCH_NAME_KEY));
            config.setSecurityPrincipal(jsonUtil.getJSONValueString(json, LDAP_SECURITY_PRINCIPAL_TAG));
            config.setPassword(jsonUtil.getJSONValueString(json, LDAP_PASSWORD_TAG));
            x = jsonUtil.getJSONValueString(json, SEARCH_FILTER_ATTRIBUTE_KEY);

            if (x != null && 0 < x.length()) {
                config.setSearchFilterAttribute(x);
            } else {
                config.setSearchFilterAttribute(SEARCH_FILTER_ATTRIBUTE_DEFAULT);
            }
            JSONObject jsonSSL = new JSONObject();
            jsonSSL.put(SSLConfigurationUtil2.SSL_TAG, jsonUtil.getJSONValue(json, SSLConfigurationUtil2.SSL_TAG));
            SSLConfiguration sslConfiguration = SSLConfigurationUtil2.fromJSON(jsonSSL);
            config.setSslConfiguration(sslConfiguration);
        }
        return config;

    }


    public LDAPConfiguration fromJSON(JSONObject json) {
        LDAPConfiguration config = new LDAPConfiguration();
        return fromJSON(config, json);
    }

}
