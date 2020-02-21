package edu.uiuc.ncsa.myproxy.oa4mp.qdl.claims;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.FSClaimSource;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.HTTPHeaderClaimsSource;
import edu.uiuc.ncsa.qdl.util.StemVariable;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.ClaimSource;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.ClaimSourceConfiguration;
import edu.uiuc.ncsa.security.oauth_2_0.server.config.LDAPConfiguration;
import edu.uiuc.ncsa.security.oauth_2_0.server.config.LDAPConfigurationUtil;

import java.util.*;

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
    /**
     * Takes a {@link ClaimSource}, grabs it configuration and turns it in to a stem
     * varaible. This is used to pass back configurations to scripts.
     * @param claimsSource
     * @param type
     * @return
     */
    public static StemVariable convert(ClaimSource claimsSource, String type) {
        StemVariable stem = new StemVariable();
        ClaimSourceConfiguration cfg = claimsSource.getConfiguration();
        setDefaultsInStem(cfg, stem);
        stem.put(CS_DEFAULT_TYPE, type); // set the type in the stem for later.
        LDAPConfiguration cfg2 = null;

        switch (type) {
            case CS_TYPE_FILE:
                stem.put(CS_FILE_FILE_PATH, cfg.getProperty(FSClaimSource.FILE_PATH_KEY));
                if (cfg.getProperty(FSClaimSource.FILE_CLAIM_KEY) != null) {
                    stem.put(CS_FILE_CLAIM_KEY, cfg.getProperty(FSClaimSource.FILE_CLAIM_KEY));
                }
                break;
            case CS_TYPE_HEADERS:
                if (cfg.getProperty(HTTPHeaderClaimsSource.PREFIX_KEY) != null) {
                    stem.put(CS_HEADERS_PREFIX, cfg.getProperty(HTTPHeaderClaimsSource.PREFIX_KEY));
                }
                break;
            case CS_TYPE_NCSA:
                cfg2 = (LDAPConfiguration) claimsSource.getConfiguration();
                stem.put(CS_LDAP_SEARCH_FILTER_ATTRIBUTE, cfg2.getSearchFilterAttribute());
                break;
            case CS_TYPE_LDAP:
                LDAPConfigurationUtil cUtil = new LDAPConfigurationUtil();

                cfg2 = (LDAPConfiguration) claimsSource.getConfiguration();
                stem.put(CS_LDAP_SEARCH_NAME, cfg2.getSearchNameKey());
                stem.put(CS_LDAP_SERVER_ADDRESS, cfg2.getServer());
                stem.put(CS_LDAP_CONTEXT_NAME, cfg2.getContextName());
                stem.put(CS_LDAP_PORT, cfg2.getPort());
                stem.put(CS_LDAP_AUTHZ_TYPE, cUtil.getAuthName(cfg2.getAuthType()));
                if (cfg2.getAuthType() == LDAPConfigurationUtil.LDAP_AUTH_SIMPLE_KEY) {
                    stem.put(CS_LDAP_PASSWORD, cfg2.getPassword());
                    stem.put(CS_LDAP_SECURITY_PRINCIPAL, cfg2.getSecurityPrincipal());
                }

                if (cfg2.getSearchAttributes() != null && !cfg2.getSearchAttributes().isEmpty()) {
                    List<Object> groups = new ArrayList<>();
                    List<Object> names = new ArrayList<>();
                    List<Object> isList = new ArrayList<>();
                    StemVariable renames = new StemVariable();
                    for (String key : cfg2.getSearchAttributes().keySet()) {
                        LDAPConfigurationUtil.AttributeEntry attributeEntry = cfg2.getSearchAttributes().get(key);
                        names.add(attributeEntry.sourceName);
                        if (attributeEntry.targetName != null && !attributeEntry.targetName.equals(attributeEntry.sourceName)) {
                            renames.put(attributeEntry.sourceName, attributeEntry.targetName);
                        }
                        if (attributeEntry.isGroup) {
                            groups.add(attributeEntry.sourceName);
                        }
                        if (attributeEntry.isList) {
                            isList.add(attributeEntry.sourceName);
                        }
                        StemVariable nameStem = new StemVariable();
                        nameStem.addList(names);
                        stem.put(CS_LDAP_SEARCH_ATTRIBUTES, nameStem);

                        if (groups.size() != 0) {
                            StemVariable groupStem = new StemVariable();
                            groupStem.addList(groups);
                            stem.put(CS_LDAP_GROUP_NAMES, groupStem);
                        }
                        if (isList.size() != 0) {
                            StemVariable listStem = new StemVariable();
                            listStem.addList(isList);
                            stem.put(CS_LDAP_LISTS, listStem);
                        }
                        if(renames.size() != 0){
                             stem.put(CS_LDAP_RENAME, renames);
                        }
                    }

                }
                break;
            default:
                throw new IllegalArgumentException("Error: Unknown source type");
        }
        return stem;
    }

    /**
     * Takes a stem variable of the configuration and returns a {@link ClaimSourceConfiguration}
     * object.
     * @param arg
     * @return
     */
    public static ClaimSourceConfiguration convert(StemVariable arg) {
        ClaimSourceConfiguration cfg = null;
        HashMap<String, Object> xp = new HashMap<>();
        switch (arg.getString(CS_DEFAULT_TYPE)) {
            case CS_TYPE_FILE:
                cfg = new ClaimSourceConfiguration();
                setDefaultsinCfg(arg, cfg);
                // Next is required although it has to be put in the properties
                xp.put(FSClaimSource.FILE_PATH_KEY, arg.getString(CS_FILE_FILE_PATH)); //  wee bit of translation
                if (arg.containsKey(CS_FILE_CLAIM_KEY)) {
                    xp.put(FSClaimSource.FILE_CLAIM_KEY, arg.getString(CS_FILE_CLAIM_KEY));
                }
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
                    Collection lists;
                    if (arg.containsKey(CS_LDAP_GROUP_NAMES)) {
                        StemVariable groupStem = (StemVariable) arg.get(CS_LDAP_GROUP_NAMES);
                        groups = groupStem.values();
                    } else {
                        groups = new ArrayList();
                    }
                    StemVariable renames = null;
                    if(arg.containsKey(CS_LDAP_RENAME)){
                        renames = (StemVariable) arg.get(CS_LDAP_RENAME);
                    }
                    if (arg.containsKey(CS_LDAP_LISTS)) {
                        StemVariable listNames = (StemVariable) arg.get(CS_LDAP_LISTS);
                        lists = listNames.values();
                    } else {
                        lists = new ArrayList();
                    }
                    for (String key : searchAttr.keySet()) {
                        String attrName = searchAttr.getString(key);
                        boolean isGroup = groups.contains(attrName);
                        boolean isList = lists.contains(attrName);
                        if (isList && isGroup) {
                            throw new IllegalArgumentException("You cannot have a \"" + attrName + "\" be both a group and a list. ");
                        }
                        String rename = attrName;
                        if(renames != null){
                            if(renames.containsKey(attrName)){
                                rename = renames.getString(attrName);
                            }
                        }
                        LDAPConfigurationUtil.AttributeEntry attributeEntry =
                                new LDAPConfigurationUtil.AttributeEntry(attrName, rename, isList, isGroup);
                        attrs.put(attrName, attributeEntry);
                    }
                    ldapCfg.setSearchAttributes(attrs);
                }


                return ldapCfg;
            case CS_TYPE_HEADERS:
                cfg = new ClaimSourceConfiguration();
                setDefaultsinCfg(arg, cfg);
                if (arg.containsKey(CS_HEADERS_PREFIX)) {
                    xp.put(HTTPHeaderClaimsSource.PREFIX_KEY, arg.getString(CS_HEADERS_PREFIX)); //  wee bit of translation
                }
                cfg.setProperties(xp);
                return cfg;

            case CS_TYPE_NCSA:
                // nothing to convert here.
        }
        return null;
    }

    protected static void setDefaultsinCfg(StemVariable arg, ClaimSourceConfiguration cfg) {
        if (arg.containsKey(CS_DEFAULT_ID)) cfg.setId(arg.getString(CS_DEFAULT_ID));
        if (arg.containsKey(CS_DEFAULT_FAIL_ON_ERROR)) cfg.setFailOnError(arg.getBoolean(CS_DEFAULT_FAIL_ON_ERROR));
        if (arg.containsKey(CS_DEFAULT_NOTIFY_ON_FAIL)) cfg.setNotifyOnFail(arg.getBoolean(CS_DEFAULT_NOTIFY_ON_FAIL));
        if (arg.containsKey(CS_DEFAULT_IS_ENABLED)) cfg.setEnabled(arg.getBoolean(CS_DEFAULT_IS_ENABLED));
        if (arg.containsKey(CS_DEFAULT_NAME)) cfg.setName(arg.getString(CS_DEFAULT_NAME));
    }

    protected static void setDefaultsInStem(ClaimSourceConfiguration cfg, StemVariable arg) {
        arg.put(CS_DEFAULT_ID, cfg.getId());
        arg.put(CS_DEFAULT_FAIL_ON_ERROR, cfg.isFailOnError());
        arg.put(CS_DEFAULT_IS_ENABLED, cfg.isEnabled());
        arg.put(CS_DEFAULT_NOTIFY_ON_FAIL, cfg.isNotifyOnFail());
        arg.put(CS_DEFAULT_NAME, cfg.getName());
    }
}
