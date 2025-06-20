package org.oa4mp.server.loader.qdl.claims;

import org.oa4mp.server.loader.oauth2.claims.BasicClaimsSourceImpl;
import org.oa4mp.server.loader.oauth2.claims.FSClaimSource;
import org.oa4mp.server.loader.oauth2.claims.HTTPHeaderClaimsSource;
import org.oa4mp.server.loader.oauth2.claims.QDLHeadersClaimsSource;
import org.qdl_lang.variables.QDLStem;
import org.oa4mp.delegation.server.server.claims.ClaimSource;
import org.oa4mp.delegation.server.server.claims.ClaimSourceConfiguration;
import org.oa4mp.delegation.server.server.config.LDAPConfiguration;
import org.oa4mp.delegation.server.server.config.LDAPConfigurationUtil;
import net.sf.json.JSONObject;

import java.util.*;

import static org.qdl_lang.variables.StemUtility.put;

/**
 * The claim source configurations made for QDL are really just the barebones defaults. The actual configurations
 * are large and sometimes nastily complex Java objects, so this configuration will convert a stem
 * variable to an actual usable {@link ClaimSourceConfiguration}
 * on a type by type basis.<br/><br/>
 * <b>NOTE</b> it is assumed that the argument has been properly created. That is why this is not a QDL
 * function.
 * <p>Created by Jeff Gaynor<br>
 * on 2/10/20 at  3:10 PM
 */
public class ClaimSourceConfigConverter implements CSConstants {
    /**
     * Takes a {@link ClaimSource}, grabs it configuration and turns it in to a stem
     * variable. This is used to pass back configurations to scripts.
     *
     * @param claimsSource
     * @param type
     * @return
     */
    public static QDLStem convert(ClaimSource claimsSource, String type) {
        QDLStem stem = new QDLStem();
        ClaimSourceConfiguration cfg = claimsSource.getConfiguration();
        setDefaultsInStem(cfg, stem);
        put(stem,CS_DEFAULT_TYPE, type); // set the type in the stem for later.
        LDAPConfiguration cfg2 = null;

        switch (type) {
            case CS_TYPE_CODE:
                if (!(claimsSource instanceof BasicClaimsSourceImpl)) {
                    throw new IllegalArgumentException(" Custom code must extend BasicClaimSourceImpl. The class \"" +
                            claimsSource.getClass().getCanonicalName() + "\" does not.");
                }
                BasicClaimsSourceImpl basicClaimsSource = (BasicClaimsSourceImpl) claimsSource;
                if (cfg.getProperty(CS_CODE_JAVA_CLASS) == null) {
                    throw new IllegalStateException("Error: No java class has been set for a custom claim source.");
                }
                for (String key : cfg.getProperties().keySet()) {
                    put(stem,key, cfg.getProperty(key)); // First cut is just use strings
                }

                break;
            case CS_TYPE_FILE:
                FSClaimSource fsClaimSource = (FSClaimSource) claimsSource;
                put(stem,CS_FILE_FILE_PATH, cfg.getProperty(FSClaimSource.FILE_PATH_KEY));
                if (cfg.getProperty(FSClaimSource.FILE_CLAIM_KEY) != null) {
                    put(stem,CS_FILE_CLAIM_KEY, cfg.getProperty(FSClaimSource.FILE_CLAIM_KEY));
                }
                put(stem,CS_USE_DEFAULT_KEY, fsClaimSource.isUseDefaultClaims());
                if (fsClaimSource.getDefaultClaimName() != null) {
                    put(stem,CS_DEFAULT_CLAIM_NAME_KEY, fsClaimSource.getDefaultClaimName());
                }
                break;
            case CS_TYPE_FILTER_HEADERS:
                if (cfg.getProperty(HTTPHeaderClaimsSource.PREFIX_KEY) != null) {
                    put(stem,CS_HEADERS_PREFIX, cfg.getProperty(HTTPHeaderClaimsSource.PREFIX_KEY));
                }
                break;
            case CS_TYPE_ALL_HEADERS:
                if (cfg.getProperty(QDLHeadersClaimsSource.PREFIX_KEY) != null) {
                    put(stem,CS_HEADERS_PREFIX, cfg.getProperty(QDLHeadersClaimsSource.PREFIX_KEY));
                }
                if (cfg.getProperty(QDLHeadersClaimsSource.REGEX_KEY) != null) {
                    put(stem,CS_HEADERS_REGEX, cfg.getProperty(QDLHeadersClaimsSource.REGEX_KEY));
                }

                break;
            case CS_TYPE_NCSA:
                cfg2 = (LDAPConfiguration) claimsSource.getConfiguration();
                put(stem,CS_LDAP_SEARCH_FILTER_ATTRIBUTE, cfg2.getSearchFilterAttribute());
                break;
            case CS_TYPE_LDAP:
                LDAPConfigurationUtil cUtil = new LDAPConfigurationUtil();

                cfg2 = (LDAPConfiguration) claimsSource.getConfiguration();
                put(stem,CS_LDAP_SEARCH_NAME, cfg2.getSearchNameKey());
                put(stem,CS_LDAP_SERVER_ADDRESS, cfg2.getServer());
                put(stem,CS_LDAP_SEARCH_BASE, cfg2.getSearchBase()); // Fixes CIL-1328
                put(stem,CS_LDAP_CONTEXT_NAME, cfg2.getContextName());
                put(stem,CS_LDAP_ADDITIONAL_FILTER, cfg2.getAdditionalFilter());
                put(stem,CS_LDAP_PORT, new Long(cfg2.getPort()));
                put(stem,CS_LDAP_AUTHZ_TYPE, cUtil.getAuthName(cfg2.getAuthType()));
                put(stem,CS_LDAP_SEARCH_FILTER_ATTRIBUTE, cfg2.getSearchFilterAttribute());
                if (cfg2.hasSearchScope()) {
                    put(stem,CS_LDAP_SEARCH_SCOPE, cfg2.getSearchScope());
                }
                if (cfg2.getAuthType() == LDAPConfigurationUtil.LDAP_AUTH_SIMPLE_KEY) {
                    put(stem,CS_LDAP_PASSWORD, cfg2.getPassword());
                    put(stem,CS_LDAP_SECURITY_PRINCIPAL, cfg2.getSecurityPrincipal());
                }

                if (cfg2.getSearchAttributes() != null && !cfg2.getSearchAttributes().isEmpty()) {
                    List<Object> groups = new ArrayList<>();
                    List<Object> names = new ArrayList<>();
                    List<Object> isList = new ArrayList<>();
                    QDLStem renames = new QDLStem();
                    for (String key : cfg2.getSearchAttributes().keySet()) {
                        LDAPConfigurationUtil.AttributeEntry attributeEntry = cfg2.getSearchAttributes().get(key);
                        names.add(attributeEntry.sourceName);
                        if (attributeEntry.targetName != null && !attributeEntry.targetName.equals(attributeEntry.sourceName)) {
                            put(renames,attributeEntry.sourceName, attributeEntry.targetName);
                        }
                        if (attributeEntry.isGroup) {
                            groups.add(attributeEntry.sourceName);
                        }
                        if (attributeEntry.isList) {
                            isList.add(attributeEntry.sourceName);
                        }
                        QDLStem nameStem = new QDLStem();
                        nameStem.addList(names);
                        put(stem,CS_LDAP_SEARCH_ATTRIBUTES, nameStem);

                        if (groups.size() != 0) {
                            QDLStem groupStem = new QDLStem();
                            groupStem.addList(groups);
                            put(stem,CS_LDAP_GROUP_NAMES, groupStem);
                        }
                        if (isList.size() != 0) {
                            QDLStem listStem = new QDLStem();
                            listStem.addList(isList);
                            put(stem,CS_LDAP_LISTS, listStem);
                        }
                        if (renames.size() != 0) {
                            put(stem,CS_LDAP_RENAME, renames);
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
     *
     * @param arg
     * @return
     */
    public static ClaimSourceConfiguration convert(QDLStem arg) {
        ClaimSourceConfiguration cfg = null;
        HashMap<String, Object> xp = new HashMap<>();
        switch (arg.getString(CS_DEFAULT_TYPE)) {
            case CS_TYPE_CODE:
                cfg = new ClaimSourceConfiguration();
                cfg.setProperties((JSONObject) arg.toJSON());
                return cfg;
            case CS_TYPE_FILE:
                cfg = new ClaimSourceConfiguration();
                setDefaultsinCfg(arg, cfg);
                // Next is required, although it has to be put in the properties
                xp.put(FSClaimSource.FILE_PATH_KEY, arg.getString(CS_FILE_FILE_PATH)); //  wee bit of translation
                if (arg.containsKey(CS_FILE_CLAIM_KEY)) {
                    xp.put(FSClaimSource.FILE_CLAIM_KEY, arg.getString(CS_FILE_CLAIM_KEY));
                }
                if (arg.containsKey(CS_USE_DEFAULT_KEY)) {
                    xp.put(FSClaimSource.USE_DEFAULT_KEY, arg.getBoolean(CS_USE_DEFAULT_KEY));
                }
                if (arg.containsKey(CS_DEFAULT_CLAIM_NAME_KEY)) {
                    xp.put(FSClaimSource.DEFAULT_CLAIM_KEY, arg.getString(CS_DEFAULT_CLAIM_NAME_KEY));
                }
                cfg.setProperties(xp);
                return cfg;
            case CS_TYPE_LDAP:

                LDAPConfiguration ldapCfg = new LDAPConfiguration();
                setDefaultsinCfg(arg, ldapCfg); // Fixes CIL-1267

                LDAPConfigurationUtil cUtil = new LDAPConfigurationUtil();
                ldapCfg.setSearchNameKey(arg.getString(CS_LDAP_SEARCH_NAME));
                ldapCfg.setServer(arg.getString(CS_LDAP_SERVER_ADDRESS));
                if (arg.containsKey(CS_LDAP_SEARCH_FILTER_ATTRIBUTE)) {
                    ldapCfg.setSearchFilterAttribute(arg.getString(CS_LDAP_SEARCH_FILTER_ATTRIBUTE));
                }
                if (arg.containsKey(CS_LDAP_SEARCH_SCOPE)) {
                    ldapCfg.setSearchScope(arg.getString(CS_LDAP_SEARCH_SCOPE));
                }

                if (arg.containsKey(CS_DEFAULT_IS_ENABLED)) {
                    ldapCfg.setEnabled(arg.getBoolean(CS_DEFAULT_IS_ENABLED));
                } else {
                    ldapCfg.setEnabled(true);
                }
                if (arg.containsKey(CS_LDAP_ADDITIONAL_FILTER)) {
                    ldapCfg.setAdditionalFilter(arg.getString(CS_LDAP_ADDITIONAL_FILTER));
                } else {
                    ldapCfg.setAdditionalFilter("");
                }
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

                ldapCfg.setAuthType(cUtil.getAuthType(arg.getString(CS_LDAP_AUTHZ_TYPE)));
                if (ldapCfg.getAuthType() == LDAPConfigurationUtil.LDAP_AUTH_SIMPLE_KEY) {
                    ldapCfg.setPassword(arg.getString(CS_LDAP_PASSWORD));
                    ldapCfg.setSecurityPrincipal(arg.getString(CS_LDAP_SECURITY_PRINCIPAL));
                }
                ldapCfg.setSearchBase(arg.getString(CS_LDAP_SEARCH_BASE));
                // now to construct the search attributes.
/*                    Example. Have to specify search_attributes explicitly or no rename possible
                      Omitting search_attributes means to get them all.
               {
                 'auth_type':'simple',
                 'password':'XXXX',
                 'address':'ldap.cilogon.org',
                 'port':636,
                 'rename':{'sn':'title'},
                 'claim_name':'uid',
                 'search_base':'ou=people,o=Fermilab,o=CO,dc=cilogon,dc=org',
                 'search_attributes':['isMemberOf','sn','cn','voPersonID'],
                 'rename' :{'isMemberOf':'is_member_of'},
                 'type':'ldap',
                 'ldap_name':'voPersonExternalID',
                 'username':'uid=oa4mp_user,ou=system,o=Fermilab,o=CO,dc=cilogon,dc=org'
               }
                 */
                QDLStem renames = null;
                if (arg.containsKey(CS_LDAP_RENAME)) {
                    renames = arg.get(CS_LDAP_RENAME).asStem();
                }
                Collection lists = null;
                if (arg.containsKey(CS_LDAP_LISTS)) {
                    QDLStem listNames = arg.get(CS_LDAP_LISTS).asStem();
                    lists = listNames.values();
                } else {
                    lists = new ArrayList();
                }

                Collection groups;
                if (arg.containsKey(CS_LDAP_GROUP_NAMES)) {
                    QDLStem groupStem = arg.get(CS_LDAP_GROUP_NAMES).asStem();
                    groups = groupStem.values();
                } else {
                    groups = new ArrayList();
                }

                if (arg.containsKey(CS_LDAP_SEARCH_ATTRIBUTES)) {
                    // no attribute means they are getting everything. Let them.
                    QDLStem searchAttr = arg.get(CS_LDAP_SEARCH_ATTRIBUTES).asStem();
                    Map<String, LDAPConfigurationUtil.AttributeEntry> attrs = new HashMap<>();

                    for (Object key : searchAttr.keySet()) {
                        String attrName = String.valueOf(searchAttr.get(key));
                        boolean isGroup = groups.contains(attrName);
                        boolean isList = lists.contains(attrName);
                        if (isList && isGroup) {
                            throw new IllegalArgumentException("You cannot have a \"" + attrName + "\" be both a group and a list. ");
                        }
                        String rename = attrName;
                        if (renames != null) {
                            if (renames.containsKey(attrName)) {
                                rename = renames.getString(attrName);
                            }
                        }
                        LDAPConfigurationUtil.AttributeEntry attributeEntry =
                                new LDAPConfigurationUtil.AttributeEntry(attrName, rename, isList, isGroup);
                        attrs.put(attrName, attributeEntry);
                    }
                    if (!attrs.isEmpty()) {
                        ldapCfg.setSearchAttributes(attrs);
                    }
                }

                return ldapCfg;
            case CS_TYPE_FILTER_HEADERS:
                cfg = new ClaimSourceConfiguration();
                setDefaultsinCfg(arg, cfg);
                if (arg.containsKey(CS_HEADERS_PREFIX)) {
                    xp.put(HTTPHeaderClaimsSource.PREFIX_KEY, arg.getString(CS_HEADERS_PREFIX)); //  wee bit of translation
                }
                cfg.setProperties(xp);
                return cfg;
            case CS_TYPE_ALL_HEADERS:
                cfg = new ClaimSourceConfiguration();
                setDefaultsinCfg(arg, cfg);
                if (arg.containsKey(CS_HEADERS_PREFIX)) {
                    xp.put(QDLHeadersClaimsSource.PREFIX_KEY, arg.getString(CS_HEADERS_PREFIX));
                }
                if (arg.containsKey(CS_HEADERS_REGEX)) {
                    xp.put(QDLHeadersClaimsSource.REGEX_KEY, arg.getString(CS_HEADERS_PREFIX));
                }

                cfg.setProperties(xp);
                return cfg;
            case CS_TYPE_NCSA:
                // nothing to convert here.
        }
        return null;
    }

    protected static void setDefaultsinCfg(QDLStem arg, ClaimSourceConfiguration cfg) {
        if (arg.containsKey(CS_DEFAULT_ID)) cfg.setId(arg.getString(CS_DEFAULT_ID));
        if (arg.containsKey(CS_DEFAULT_FAIL_ON_ERROR)) cfg.setFailOnError(arg.getBoolean(CS_DEFAULT_FAIL_ON_ERROR));
        if (arg.containsKey(CS_DEFAULT_NOTIFY_ON_FAIL)) cfg.setNotifyOnFail(arg.getBoolean(CS_DEFAULT_NOTIFY_ON_FAIL));
        if (arg.containsKey(CS_DEFAULT_IS_ENABLED)) cfg.setEnabled(arg.getBoolean(CS_DEFAULT_IS_ENABLED));
        if (arg.containsKey(CS_DEFAULT_NAME)) cfg.setName(arg.getString(CS_DEFAULT_NAME));
        if (arg.containsKey(CS_LDAP_MAX_RETRY_SLEEP)) {
            cfg.setMaxWait(arg.getLong(CS_LDAP_MAX_RETRY_SLEEP));
        }
        if (arg.containsKey(CS_LDAP_RETRY_COUNT)) {
            cfg.setRetryCount(Math.toIntExact(arg.getLong(CS_LDAP_RETRY_COUNT)));
        }
    }

    protected static void setDefaultsInStem(ClaimSourceConfiguration cfg, QDLStem arg) {
        put(arg,CS_DEFAULT_ID, cfg.getId());
        put(arg,CS_DEFAULT_FAIL_ON_ERROR, cfg.isFailOnError());
        put(arg,CS_DEFAULT_IS_ENABLED, cfg.isEnabled());
        put(arg,CS_DEFAULT_NOTIFY_ON_FAIL, cfg.isNotifyOnFail());
        put(arg,CS_DEFAULT_NAME, cfg.getName());
        put(arg,CS_LDAP_RETRY_COUNT, (long) cfg.getRetryCount());
        put(arg,CS_LDAP_MAX_RETRY_SLEEP, cfg.getMaxWait());

    }
}
