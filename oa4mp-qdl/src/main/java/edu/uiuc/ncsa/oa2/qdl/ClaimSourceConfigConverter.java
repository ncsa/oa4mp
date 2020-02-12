package edu.uiuc.ncsa.oa2.qdl;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.FSClaimSource;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.HTTPHeaderClaimsSource;
import edu.uiuc.ncsa.qdl.util.StemVariable;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.ClaimSourceConfiguration;
import edu.uiuc.ncsa.security.oauth_2_0.server.config.LDAPConfiguration;
import edu.uiuc.ncsa.security.oauth_2_0.server.config.LDAPConfigurationUtil;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

/**
 * The claim source configurations made for QDL are really just the barebones defaults. The actual configurations
 * are large and sometimes nastily complex Java objects, so this configuration will convert a stem
 * variable to an actual usable {@link edu.uiuc.ncsa.security.oauth_2_0.server.claims.ClaimSourceConfiguration}
 * on a type by type basis.<br/><br/>
 * <b>NOTE</b> it is assumed that the argument has been properly created. That is why this is not a QDL
 * function.
 * <p>Created by Jeff Gaynor<br>
 * on 2/10/20 at  3:10 PM
 */
public class ClaimSourceConfigConverter implements CSConstants {
    public static ClaimSourceConfiguration convert(StemVariable arg) {
        ClaimSourceConfiguration cfg = null;
        HashMap<String, Object> xp = new HashMap<>();
        switch (arg.getString(CS_DEFAULT_TYPE)) {
            case CS_TYPE_FILE:
                cfg = new ClaimSourceConfiguration();
                setDefaults(cfg, arg);
                // Next is required although it has to be put in the properties
                xp.put(FSClaimSource.FILE_PATH_KEY, arg.getString(CS_FILE_FILE_PATH)); //  wee bit of translation
                cfg.setProperties(xp);
                return cfg;
            case CS_TYPE_LDAP:

                LDAPConfiguration ldapCfg = new LDAPConfiguration();
                LDAPConfigurationUtil cUtil = new LDAPConfigurationUtil();
                ldapCfg.setSearchNameKey(arg.getString(CS_LDAP_SEARCH_NAME));
                ldapCfg.setServer(arg.getString(CS_LDAP_SERVER_ADDRESS));
                ldapCfg.setEnabled(arg.getBoolean(CS_DEFAULT_IS_ENABLED));
                if (arg.containsKey(CS_LDAP_CONTEXT_NAME)) {
                    ldapCfg.setContextName(arg.getString(CS_LDAP_CONTEXT_NAME));
                } else {
                    ldapCfg.setContextName("");// default. MUST be present of the search internally throws an NPE...
                }
                if (arg.containsKey(CS_LDAP_PORT)) {
                    ldapCfg.setPort(arg.getLong(CS_LDAP_PORT).intValue());
                } else {
                    ldapCfg.setPort(LDAPConfigurationUtil.DEFAULT_PORT);
                }
                if (arg.containsKey(CS_DEFAULT_ID)) {
                    ldapCfg.setId(arg.getString(CS_DEFAULT_ID));
                } else {
                    ldapCfg.setId(CS_DEFAULT_ID_VALUE);
                }
                ldapCfg.setAuthType(cUtil.getAuthType(arg.getString(CS_LDAP_AUTHZ_TYPE)));
                if (ldapCfg.getAuthType() == LDAPConfigurationUtil.LDAP_AUTH_SIMPLE_KEY) {
                    ldapCfg.setPassword(arg.getString(CS_LDAP_PASSWORD));
                    ldapCfg.setSecurityPrincipal(arg.getString(CS_LDAP_SECURITY_PRINCIPAL));
                }
                ldapCfg.setSearchBase(arg.getString(CS_LDAP_SEARCH_BASE));
                // now to construct the search attributes.
                if (arg.containsKey(CS_LDAP_SEARCH_ATTRIBUTES)) {
                    // no attribute means they are getting everything. Let them.
                    StemVariable searchAttr = (StemVariable) arg.get(CS_LDAP_SEARCH_ATTRIBUTES);
                    Map<String, LDAPConfigurationUtil.AttributeEntry> attrs = new HashMap<>();
                    Collection groups;
                    if (arg.containsKey(CS_LDAP_GROUP_NAMES)) {
                        StemVariable groupStem = (StemVariable) arg.get(CS_LDAP_GROUP_NAMES);
                        groups = groupStem.values();
                    } else {
                        groups = new ArrayList();
                    }
                    for (String key : searchAttr.keySet()) {
                        String attrName = searchAttr.getString(key);
                        boolean isGroup = groups.contains(attrName);
                        LDAPConfigurationUtil.AttributeEntry attributeEntry =
                                new LDAPConfigurationUtil.AttributeEntry(attrName, attrName, false, isGroup);
                        attrs.put(attrName, attributeEntry);
                    }
                    ldapCfg.setSearchAttributes(attrs);
                }


                return ldapCfg;
            case CS_TYPE_HEADERS:
                cfg = new ClaimSourceConfiguration();
                setDefaults(cfg, arg);
                if (arg.containsKey(CS_HEADERS_PREFIX)) {
                    xp.put(HTTPHeaderClaimsSource.PREFIX_KEY, arg.getString(CS_HEADERS_PREFIX)); //  wee bit of translation
                }
                cfg.setProperties(xp);
                return cfg;

            case CS_TYPE_NCSA:
        }
        return null;
    }

    protected static void setDefaults(ClaimSourceConfiguration cfg, StemVariable arg) {
        if (arg.containsKey(CS_DEFAULT_ID)) cfg.setId(arg.getString(CS_DEFAULT_ID));
        if (arg.containsKey(CS_DEFAULT_FAIL_ON_ERROR)) cfg.setFailOnError(arg.getBoolean(CS_DEFAULT_FAIL_ON_ERROR));
        if (arg.containsKey(CS_DEFAULT_NOTIFY_ON_FAIL)) cfg.setNotifyOnFail(arg.getBoolean(CS_DEFAULT_NOTIFY_ON_FAIL));
        if (arg.containsKey(CS_DEFAULT_IS_ENABLED)) cfg.setEnabled(arg.getBoolean(CS_DEFAULT_IS_ENABLED));
        if (arg.containsKey(CS_DEFAULT_NAME)) cfg.setName(arg.getString(CS_DEFAULT_NAME));
    }
}
